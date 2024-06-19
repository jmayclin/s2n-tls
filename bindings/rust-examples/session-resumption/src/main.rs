use std::sync::{atomic::{AtomicU64, Ordering}, Arc};

use session_resumption::{repro_trial, NUM_HARNESS_THREADS};

// nohup ./target/release/session-resumption > output.log 2>&1 &
fn main() {
    let trials = Arc::new(AtomicU64::new(0));
    // 16 cores, each spawns two threads, so 16 threads -> 64 trials
    let mut handles = Vec::new();
    for _ in 0..NUM_HARNESS_THREADS {
        let trials_handle = Arc::clone(&trials);
        let handle = std::thread::spawn(move || {
            let mut seed = 0;
            loop {
                if trials_handle.load(Ordering::Relaxed) % 10000 == 0 {
                    println!("trials: {:?}", trials_handle.load(Ordering::Relaxed));
                }
                trials_handle.fetch_add(1, Ordering::Relaxed);
                seed += 1;
                seed %= 100;
                if let Err(e) = repro_trial(seed + 1) {
                    println!("hit the zero name");
                    std::fs::write(
                        format!("trial{}", trials_handle.load(Ordering::Relaxed)),
                        "zero stek name",
                    )
                    .unwrap();
                }
            };
        });
        handles.push(handle);
    }
    for h in handles {
        h.join().unwrap();
    }
}
