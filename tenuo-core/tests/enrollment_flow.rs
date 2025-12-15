use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

struct ProcessGuard(std::process::Child);

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn test_enrollment_flow() {
    // 1. Build binaries
    let status = Command::new("cargo")
        .args([
            "build",
            "--bin",
            "tenuo-control",
            "--bin",
            "tenuo-orchestrator",
            "--features",
            "control-plane server",
        ])
        .status()
        .expect("Failed to build binaries");
    assert!(status.success(), "Build failed");

    // 2. Start Control Plane
    let control = Command::new("target/debug/tenuo-control")
        .env("TENUO_BIND_ADDR", "127.0.0.1:8084") // Use different port
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start control plane");

    // Wrap in guard to ensure cleanup on panic
    let mut control_guard = ProcessGuard(control);

    // 3. Read stdout to find ENROLLMENT TOKEN
    let stdout = control_guard.0.stdout.take().expect("Failed to open stdout");
    let stderr = control_guard.0.stderr.take().expect("Failed to open stderr");
    let reader = BufReader::new(stdout);
    let err_reader = BufReader::new(stderr);

    // Spawn a thread to read stdout so we don't block
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for line in reader.lines().map_while(Result::ok) {
            println!("[CONTROL] {}", line);
            if line.contains("ENROLLMENT TOKEN:") {
                let parts: Vec<&str> = line.split("ENROLLMENT TOKEN: ").collect();
                if parts.len() > 1 {
                    let token = parts[1].trim().trim_matches('║').trim();
                    tx.send(token.to_string()).unwrap();
                }
            }
        }
    });

    // Spawn a thread to read stderr
    thread::spawn(move || {
        for line in err_reader.lines().map_while(Result::ok) {
            eprintln!("[CONTROL ERR] {}", line);
        }
    });

    // Wait for token (timeout 10s)
    let enrollment_token = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("Timed out waiting for enrollment token");
    println!("Found Enrollment Token: {}", enrollment_token);

    // 4. Start Orchestrator A with Token
    println!("Starting Orchestrator A...");
    let status_a = Command::new("target/debug/tenuo-orchestrator")
        .env("TENUO_ENROLLMENT_TOKEN", &enrollment_token)
        .env("TENUO_CONTROL_URL", "http://127.0.0.1:8084")
        .env("TENUO_WORKER_KEY_OUTPUT", "/tmp/worker_a.key")
        .env("TENUO_ADMIN_KEY_OUTPUT", "/tmp/admin_a.key")
        .env("TENUO_CHAIN_OUTPUT", "/tmp/chain_a.json")
        .status()
        .expect("Failed to start orchestrator A");
    assert!(status_a.success(), "Orchestrator A failed");

    // 5. Start Orchestrator B with SAME Token (Multi-Swarm Test)
    println!("Starting Orchestrator B (Multi-Swarm Test)...");
    let status_b = Command::new("target/debug/tenuo-orchestrator")
        .env("TENUO_ENROLLMENT_TOKEN", &enrollment_token)
        .env("TENUO_CONTROL_URL", "http://127.0.0.1:8084")
        .env("TENUO_WORKER_KEY_OUTPUT", "/tmp/worker_b.key")
        .env("TENUO_ADMIN_KEY_OUTPUT", "/tmp/admin_b.key")
        .env("TENUO_CHAIN_OUTPUT", "/tmp/chain_b.json")
        .status()
        .expect("Failed to start orchestrator B");
    assert!(status_b.success(), "Orchestrator B failed");

    // 6. Cleanup happens automatically via Drop
}
