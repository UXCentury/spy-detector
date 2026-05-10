//! Per-(pid, peer) interval tracker that flags periodic outbound traffic
//! ("beaconing"). Scans are typically on-demand, so the tracker only
//! produces a meaningful signal when scans are repeated by the user;
//! that is acceptable for v1 — the alternative would be a continuous
//! polling loop, which is out of scope until ETW network providers are
//! wired up.
//!
//! The detector keeps the last N timestamps for each `(pid, ip, port)`
//! triple, then flags a peer as beaconing when:
//!   * we have at least `MIN_SAMPLES` observations,
//!   * the mean inter-arrival interval is between 10s and 1h, and
//!   * the coefficient of variation (stddev / mean) is below 0.25.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX_SAMPLES: usize = 20;
const MIN_SAMPLES: usize = 5;
const MIN_MEAN_SECS: f64 = 10.0;
const MAX_MEAN_SECS: f64 = 3600.0;
const MAX_JITTER: f64 = 0.25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerKey {
    pub pid: u32,
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct BeaconHit {
    pub key: PeerKey,
    pub mean_secs: f64,
    pub jitter: f64,
}

#[derive(Debug, Default)]
pub struct BeaconTracker {
    samples: HashMap<PeerKey, Vec<Instant>>,
}

impl BeaconTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, key: PeerKey, now: Instant) {
        let v = self.samples.entry(key).or_default();
        v.push(now);
        if v.len() > MAX_SAMPLES {
            let drop = v.len() - MAX_SAMPLES;
            v.drain(0..drop);
        }
    }

    pub fn evaluate(&self, key: &PeerKey) -> Option<BeaconHit> {
        let v = self.samples.get(key)?;
        if v.len() < MIN_SAMPLES {
            return None;
        }
        let intervals: Vec<f64> = v
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .collect();
        intervals_to_hit(*key, &intervals)
    }

    pub fn keys_for_pid<'a>(&'a self, pid: u32) -> impl Iterator<Item = &'a PeerKey> + 'a {
        self.samples.keys().filter(move |k| k.pid == pid)
    }

    pub fn prune_older_than(&mut self, ttl: Duration, now: Instant) {
        self.samples.retain(|_, v| {
            if let Some(last) = v.last() {
                now.duration_since(*last) <= ttl
            } else {
                false
            }
        });
    }
}

fn intervals_to_hit(key: PeerKey, intervals: &[f64]) -> Option<BeaconHit> {
    if intervals.len() < MIN_SAMPLES - 1 {
        return None;
    }
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if !(MIN_MEAN_SECS..=MAX_MEAN_SECS).contains(&mean) {
        return None;
    }
    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();
    let jitter = if mean > 0.0 {
        stddev / mean
    } else {
        f64::INFINITY
    };
    if jitter < MAX_JITTER {
        Some(BeaconHit {
            key,
            mean_secs: mean,
            jitter,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn key(pid: u32, port: u16) -> PeerKey {
        PeerKey {
            pid,
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port,
        }
    }

    fn observe_intervals(t: &mut BeaconTracker, k: PeerKey, intervals_secs: &[f64]) {
        let mut now = Instant::now();
        t.observe(k, now);
        for s in intervals_secs {
            now += Duration::from_millis((s * 1000.0) as u64);
            t.observe(k, now);
        }
    }

    #[test]
    fn metronomic_intervals_flagged() {
        let mut tracker = BeaconTracker::new();
        let k = key(42, 443);
        observe_intervals(&mut tracker, k, &[30.0, 30.0, 30.0, 30.0, 30.0, 30.0]);
        let hit = tracker.evaluate(&k).expect("metronomic must beacon");
        assert!(
            (hit.mean_secs - 30.0).abs() < 0.5,
            "mean ~30s, got {}",
            hit.mean_secs
        );
        assert!(
            hit.jitter < 0.05,
            "jitter must be near 0, got {}",
            hit.jitter
        );
    }

    #[test]
    fn noisy_metronomic_within_threshold_flagged() {
        let mut tracker = BeaconTracker::new();
        let k = key(7, 8443);
        observe_intervals(&mut tracker, k, &[28.0, 32.0, 29.0, 31.0, 30.0, 28.5]);
        let hit = tracker.evaluate(&k).expect("low jitter must beacon");
        assert!(hit.jitter < MAX_JITTER);
    }

    #[test]
    fn irregular_intervals_not_flagged() {
        let mut tracker = BeaconTracker::new();
        let k = key(99, 80);
        observe_intervals(&mut tracker, k, &[3.0, 90.0, 12.0, 600.0, 4.0, 200.0]);
        assert!(tracker.evaluate(&k).is_none());
    }

    #[test]
    fn too_few_samples_not_flagged() {
        let mut tracker = BeaconTracker::new();
        let k = key(11, 22);
        observe_intervals(&mut tracker, k, &[30.0, 30.0]);
        assert!(tracker.evaluate(&k).is_none());
    }

    #[test]
    fn too_fast_mean_not_flagged() {
        let mut tracker = BeaconTracker::new();
        let k = key(13, 1234);
        observe_intervals(&mut tracker, k, &[2.0, 2.0, 2.0, 2.0, 2.0, 2.0]);
        assert!(
            tracker.evaluate(&k).is_none(),
            "sub-10s mean must be excluded"
        );
    }

    #[test]
    fn samples_capped_at_max() {
        let mut tracker = BeaconTracker::new();
        let k = key(1, 1);
        let mut now = Instant::now();
        for _ in 0..(MAX_SAMPLES + 10) {
            tracker.observe(k, now);
            now += Duration::from_secs(1);
        }
        assert_eq!(tracker.samples.get(&k).unwrap().len(), MAX_SAMPLES);
    }
}
