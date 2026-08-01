use rand::seq::SliceRandom;
use rand::Rng;
use std::cmp::Ordering;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::time::{interval, timeout, MissedTickBehavior};

#[macro_use]
extern crate serde_json;

/// Maximum queries per second sent to any single DNS server.
const MAX_REQUESTS_PER_SECOND: f64 = 5.0;
/// Maximum in-flight (pending) queries allowed per DNS server.
const MAX_PENDING_PER_SERVER: usize = 5;
/// Any query taking longer than this is counted as a timeout (failure).
const QUERY_TIMEOUT: Duration = Duration::from_millis(500);

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

    // The whole exchange (send + receive) shares a single QUERY_TIMEOUT budget.
    let exchange = timeout(QUERY_TIMEOUT, async {
        socket
            .send_to(&query, &server_addr)
            .await
            .map_err(|e| format!("Failed to send DNS query: {}", e))?;

        let mut buf = [0u8; 512];
        let (size, _) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("Failed to receive DNS response: {}", e))?;

        if size > 0 {
            Ok(())
        } else {
            Err("No response received".to_string())
        }
    })
    .await;

    match exchange {
        Err(_) => Err(format!("Timeout (>{}ms)", QUERY_TIMEOUT.as_millis())),
        Ok(Err(e)) => Err(e),
        Ok(Ok(())) => {
            let elapsed = start.elapsed();
            // Even if the response arrived, anything over the budget counts as a timeout.
            if elapsed > QUERY_TIMEOUT {
                Err(format!("Timeout (>{}ms)", QUERY_TIMEOUT.as_millis()))
            } else {
                Ok(elapsed)
            }
        }
    }
}

fn build_dns_query(domain: &str) -> Vec<u8> {
    let transaction_id: u16 = rand::thread_rng().gen();

    let mut query: Vec<u8> = Vec::new();

    // DNS header
    query.extend(&transaction_id.to_be_bytes()); // Transaction ID (actually randomized now)
    query.extend(&[
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

async fn run_tests(dns_servers: Vec<DnsServer>, domains: Vec<String>) -> Vec<DnsResult> {
    let num_servers = dns_servers.len();
    let domains = Arc::new(domains);

    let (sender, mut receiver) = mpsc::channel::<(usize, Result<Duration, String>)>(
        (num_servers * MAX_PENDING_PER_SERVER).max(1),
    );

    // Spawn the results processing task
    let results_handle =
        tokio::spawn(async move { process_results(&mut receiver, num_servers).await });

    // One independent task per server, each with its own rate limit and pending cap
    let mut server_handles = Vec::with_capacity(num_servers);
    for (server_idx, server) in dns_servers.into_iter().enumerate() {
        let domains = Arc::clone(&domains);
        let sender = sender.clone();
        server_handles.push(tokio::spawn(run_server_tests(
            server, server_idx, domains, sender,
        )));
    }

    drop(sender); // Close the sender to signal no more tasks

    for handle in server_handles {
        let _ = handle.await;
    }

    // Wait for the results processing task to complete
    results_handle.await.expect("Failed to process results")
}

async fn run_server_tests(
    server: DnsServer,
    server_idx: usize,
    domains: Arc<Vec<String>>,
    sender: mpsc::Sender<(usize, Result<Duration, String>)>,
) {
    // Cap on in-flight queries for this server
    let pending = Arc::new(Semaphore::new(MAX_PENDING_PER_SERVER));

    // Rate limiter: one launch slot every 1/MAX_REQUESTS_PER_SECOND seconds.
    // Delay (rather than burst) if we fall behind while waiting on the pending cap.
    let mut ticker = interval(Duration::from_secs_f64(1.0 / MAX_REQUESTS_PER_SECOND));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Randomize the order this server walks through the domain list
    let mut domain_order: Vec<usize> = (0..domains.len()).collect();
    domain_order.shuffle(&mut rand::thread_rng());

    let mut query_handles = Vec::with_capacity(domain_order.len());
    for domain_idx in domain_order {
        // Backpressure: wait for a free pending slot on this server...
        let permit = Arc::clone(&pending)
            .acquire_owned()
            .await
            .expect("Semaphore closed unexpectedly");
        // ...then wait for the next rate-limit slot.
        ticker.tick().await;

        let random_domain = generate_random_subdomain(&domains[domain_idx]);
        let server_ip = server.ip.clone();
        let sender = sender.clone();

        query_handles.push(tokio::spawn(async move {
            let result = raw_dns_query(&server_ip, &random_domain).await;
            let _ = sender.send((server_idx, result)).await;
            drop(permit); // Release this server's pending slot
        }));
    }

    // Wait for this server's in-flight queries to finish
    for handle in query_handles {
        let _ = handle.await;
    }
}

async fn process_results(
    receiver: &mut mpsc::Receiver<(usize, Result<Duration, String>)>,
    num_servers: usize,
) -> Vec<DnsResult> {
    let mut results = vec![DnsResult::default(); num_servers];
    while let Some((server_idx, result)) = receiver.recv().await {
        match result {
            Ok(duration) => results[server_idx].successes.push(duration),
            Err(_) => results[server_idx].failures += 1,
        }
    }
    results
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
    println!(
        "Per-server limits: {} req/s, {} max pending, {}ms timeout",
        MAX_REQUESTS_PER_SECOND,
        MAX_PENDING_PER_SERVER,
        QUERY_TIMEOUT.as_millis()
    );
    let results = run_tests(dns_servers.clone(), domains).await;
    process_and_save_results(&dns_servers, results, "results.json");
    println!("Benchmark completed. Results saved to results.json");
}
