use rand::seq::SliceRandom;
use rand::Rng;
use std::cmp::Ordering;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[macro_use]
extern crate serde_json;

const CONCURRENCY: usize = 100;

#[derive(Clone, Debug)]
struct DnsServer {
    name: String,
    ip: String,
}

#[derive(Default, Clone, Debug)]
struct DnsResult {
    successes: Vec<Duration>,
    failures: usize,
}

fn read_dns_servers(file_path: &str) -> Vec<DnsServer> {
    fs::read_to_string(file_path)
        .expect("Failed to read dns_servers.txt")
        .lines()
        .map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            DnsServer {
                name: parts[0].to_string(),
                ip: parts[1].to_string(),
            }
        })
        .collect()
}

fn read_domains(file_path: &str) -> Vec<String> {
    fs::read_to_string(file_path)
        .expect("Failed to read domains.txt")
        .lines()
        .map(|line| line.to_string())
        .collect()
}

fn generate_random_subdomain(domain: &str) -> String {
    let random_string: String = rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    format!("{}.{}", random_string, domain)
}

fn generate_global_permutation(num_servers: usize, num_domains: usize) -> Vec<(usize, usize)> {
    let mut indices: Vec<(usize, usize)> = (0..num_servers)
        .flat_map(|server_idx| (0..num_domains).map(move |domain_idx| (server_idx, domain_idx)))
        .collect();

    let mut rng = rand::thread_rng();
    indices.shuffle(&mut rng);

    indices
}

async fn raw_dns_query(dns_server_ip: &str, domain: &str) -> Result<Duration, String> {
    let socket = if dns_server_ip.contains(':') {
        // IPv6 socket
        UdpSocket::bind("[::]:0").await
    } else {
        // IPv4 socket
        UdpSocket::bind("0.0.0.0:0").await
    }
    .map_err(|e| format!("Failed to bind socket: {}", e))?;

    let query = build_dns_query(domain);

    let server_addr = if dns_server_ip.contains(':') {
        format!("[{}]:53", dns_server_ip) // IPv6 requires brackets
    } else {
        format!("{}:53", dns_server_ip) // IPv4
    };

    let start = Instant::now();

    timeout(Duration::from_secs(1), socket.send_to(&query, &server_addr))
        .await
        .map_err(|_| "Send timeout".to_string())?
        .map_err(|e| format!("Failed to send DNS query: {}", e))?;

    let mut buf = [0u8; 512];

    let (size, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
        .await
        .map_err(|_| "Receive timeout".to_string())?
        .map_err(|e| format!("Failed to receive DNS response: {}", e))?;

    if size > 0 {
        Ok(start.elapsed())
    } else {
        Err("No response received".into())
    }
}

fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut query: Vec<u8> = Vec::new();

    // DNS header
    query.extend(&[
        0x12, 0x34, // Transaction ID (randomized)
        0x01, 0x00, // Flags (standard query)
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ]);

    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend(part.as_bytes());
    }
    query.push(0);

    query.extend(&[
        0x00, 0x01, // QTYPE: A (IPv4 address)
        0x00, 0x01, // QCLASS: IN (Internet)
    ]);

    query
}

async fn run_tests(
    dns_servers: Vec<DnsServer>,
    domains: Vec<String>,
    max_concurrent_tasks: usize,
) -> Vec<DnsResult> {
    let len = dns_servers.len() as u8;
    let dns_servers = Arc::new(dns_servers);
    let domains = Arc::new(domains);
    let semaphore = Arc::new(Semaphore::new(max_concurrent_tasks));
    let global_permutation = generate_global_permutation(dns_servers.len(), domains.len());

    let (sender, mut receiver) = mpsc::channel::<(usize, Result<Duration, String>)>(CONCURRENCY);

    // Spawn the results processing task
    let results_handle = tokio::spawn(async move { process_results(&mut receiver, len).await });

    // Spawn DNS query tasks
    for (server_idx, domain_idx) in global_permutation {
        let random_domain = generate_random_subdomain(&domains[domain_idx]);
        let dns_servers = Arc::clone(&dns_servers);
        let semaphore = Arc::clone(&semaphore);
        let sender = sender.clone();

        tokio::spawn(async move {
            let server = &dns_servers[server_idx];
            run_dns(semaphore, &server.ip, server_idx, &random_domain, sender).await;
        });
    }

    drop(sender); // Close the sender to signal no more tasks

    // Wait for the results processing task to complete
    results_handle.await.expect("Failed to process results")
}

async fn process_results(
    receiver: &mut mpsc::Receiver<(usize, Result<Duration, String>)>,
    len: u8,
) -> Vec<DnsResult> {
    let mut results = vec![DnsResult::default(); len as usize];
    while let Some((server_idx, result)) = receiver.recv().await {
        match result {
            Ok(duration) => results[server_idx].successes.push(duration),
            Err(_) => results[server_idx].failures += 1,
        }
    }
    results
}

async fn run_dns(
    semaphore: Arc<Semaphore>,
    server_ip: &str,
    server_index: usize,
    domain: &str,
    reporter: mpsc::Sender<(usize, Result<Duration, String>)>,
) {
    let _permit = semaphore.acquire().await.unwrap();
    let result = raw_dns_query(server_ip, domain).await;
    let _ = reporter.send((server_index, result)).await;
}

fn process_and_save_results(dns_servers: &[DnsServer], results: Vec<DnsResult>, file_name: &str) {
    let output: Vec<_> = dns_servers
        .iter()
        .zip(results.iter())
        .map(|(server, result)| server_stats_to_json(server, result))
        .collect();

    fs::write(file_name, serde_json::to_string_pretty(&output).unwrap())
        .expect("Failed to write results to file");
}

fn server_stats_to_json(server: &DnsServer, result: &DnsResult) -> serde_json::Value {
    // Collect raw response times in milliseconds
    let mut raw_response_times_ms: Vec<f64> = result
        .successes
        .iter()
        .map(|&duration| duration.as_secs_f64() * 1000.0)
        .collect();

    raw_response_times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal)); // Sort for percentile calculations

    // Calculate statistics
    let count = raw_response_times_ms.len();
    let min = raw_response_times_ms.first().copied().unwrap_or(0.0);
    let max = raw_response_times_ms.last().copied().unwrap_or(0.0);
    let median = calculate_percentile(&raw_response_times_ms, 50.0);
    let p25 = calculate_percentile(&raw_response_times_ms, 25.0);
    let p75 = calculate_percentile(&raw_response_times_ms, 75.0);

    json!({
        "name": server.name,
        "ip": server.ip,
        "min_response_time_ms": min,
        "max_response_time_ms": max,
        "median_response_time_ms": median,
        "25th_percentile_ms": p25,
        "75th_percentile_ms": p75,
        "failures": result.failures,
        "successes": count,
    })
}

fn calculate_percentile(data: &[f64], percentile: f64) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let rank = percentile / 100.0 * (data.len() as f64 - 1.0);
    let lower_idx = rank.floor() as usize;
    let upper_idx = rank.ceil() as usize;
    if lower_idx == upper_idx {
        data[lower_idx]
    } else {
        let weight = rank - lower_idx as f64;
        data[lower_idx] * (1.0 - weight) + data[upper_idx] * weight
    }
}

#[tokio::main]
async fn main() {
    let dns_servers = read_dns_servers("dns_servers.txt");
    let domains = read_domains("domains.txt");
    println!("Starting DNS Benchmark...");
    let results = run_tests(dns_servers.clone(), domains, CONCURRENCY).await;
    process_and_save_results(&dns_servers, results, "results.json");
    println!("Benchmark completed. Results saved to results.json");
}
