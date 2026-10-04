//! Key selection strategies.
//!
//! A strategy receives the candidate keys that are *known to be viable* and
//! picks one. Availability filtering and rate-limit accounting happen before
//! selection, so a strategy can never return a key that is on cooldown or out
//! of quota.

use std::time::Duration;

use crate::core::key_state::{KeyState, rand_unit};

/// Load balancing strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /// Deterministic rotation.
    #[default]
    RoundRobin,
    /// Weighted random within a rotation tolerance.
    WeightedRandom,
    /// Fewest in-flight requests.
    LeastBusy,
    /// Fastest observed latency (EWMA).
    LeastLatency,
    /// Lowest current RPM+TPM utilisation against the configured limits.
    UsageBased,
    /// Weighted random by remaining capacity, spreading bursty traffic.
    PowerOfTwo,
    /// Ordered failover: always prefer the first healthy key.
    Fallback,
}

impl Strategy {
    /// Parse a config string, accepting the historical names.
    pub fn parse(name: &str) -> Option<Self> {
        let normalized = name.trim().to_ascii_lowercase().replace('-', "_");
        Some(match normalized.as_str() {
            "round_robin" | "roundrobin" | "deterministic" | "simple_shuffle" | "shuffle" => {
                Strategy::RoundRobin
            }
            "weighted_random" | "weighted" | "random" => Strategy::WeightedRandom,
            "least_busy" | "least_used" | "least_connections" | "least_inflight" => {
                Strategy::LeastBusy
            }
            "least_latency" | "latency_based" | "latency_based_routing" | "fastest" => {
                Strategy::LeastLatency
            }
            "usage_based" | "usage_based_routing" | "usage" => Strategy::UsageBased,
            "power_of_two" | "p2c" | "power_of_two_choices" => Strategy::PowerOfTwo,
            "fallback" | "failover" | "priority" => Strategy::Fallback,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Strategy::RoundRobin => "round_robin",
            Strategy::WeightedRandom => "weighted_random",
            Strategy::LeastBusy => "least_busy",
            Strategy::LeastLatency => "least_latency",
            Strategy::UsageBased => "usage_based",
            Strategy::PowerOfTwo => "power_of_two",
            Strategy::Fallback => "fallback",
        }
    }

    /// Every strategy, used by the admin API to document valid values.
    pub fn all() -> &'static [Strategy] {
        &[
            Strategy::RoundRobin,
            Strategy::WeightedRandom,
            Strategy::LeastBusy,
            Strategy::LeastLatency,
            Strategy::UsageBased,
            Strategy::PowerOfTwo,
            Strategy::Fallback,
        ]
    }
}

/// A candidate key plus its currently observed rates, captured once so the
/// scoring functions do not re-lock every key several times.
#[derive(Debug, Clone, Copy)]
pub struct Candidate {
    pub index: usize,
    pub in_flight: u32,
    pub weight: u32,
    pub latency_ms: Option<f64>,
    pub rpm: u64,
    pub tpm: u64,
    pub max_rpm: Option<u32>,
    pub max_tpm: Option<u64>,
    pub health_score: f64,
}

impl Candidate {
    pub fn snapshot(index: usize, key: &KeyState) -> Self {
        let (rpm, tpm) = key.observed_rates();
        Self {
            index,
            in_flight: key.in_flight(),
            weight: key.weight,
            latency_ms: key.latency_ms(),
            rpm,
            tpm,
            max_rpm: key.max_rpm(),
            max_tpm: key.max_tpm(),
            health_score: key.health_score(),
        }
    }

    /// Fraction of the configured quota already consumed, `0.0..=1.0`.
    /// Keys without configured limits report the raw observed rate instead so
    /// they still participate in relative comparison.
    pub fn utilisation(&self) -> f64 {
        let rpm_ratio = match self.max_rpm {
            Some(max) if max > 0 => self.rpm as f64 / f64::from(max),
            _ => self.rpm as f64 / 1_000.0,
        };
        let tpm_ratio = match self.max_tpm {
            Some(max) if max > 0 => self.tpm as f64 / max as f64,
            _ => self.tpm as f64 / 1_000_000.0,
        };
        rpm_ratio.max(tpm_ratio).clamp(0.0, 1.0)
    }

    /// Relative selection weight: configured weight scaled by free capacity
    /// and health, never zero.
    pub fn effective_weight(&self) -> f64 {
        let headroom = (1.0 - self.utilisation()).max(0.05);
        let health = self.health_score.clamp(0.05, 1.0);
        (f64::from(self.weight) * headroom * health).max(1e-3)
    }

    /// Latency rank for `least_latency`: explore first, then exploit.
    ///
    /// `latency_ms` is `None` until a key has served a request. Treating that as
    /// "infinitely slow" means a key is only chosen once every *other* key has a
    /// measurement -- and since a fast, healthy winner keeps winning, the rest
    /// are never measured at all. Measured: 30/0/0 across three runs.
    ///
    /// Ranking an unmeasured key *first* fixes that. `best_by` rotates among
    /// equal scores, so the unmeasured keys are visited in turn, each gets a
    /// measurement, and only then does the fastest one start to dominate --
    /// which is what someone choosing `least_latency` is asking for, now over a
    /// pool that has actually been tried.
    /// Coarse health bucket, so small differences do not defeat tie-breaking.
    ///
    /// `0` is a healthy key. A key has to fall a full tier before it loses to
    /// an idle peer, which is what keeps a pool of healthy keys sharing load
    /// while still routing around one that is genuinely failing.
    pub fn health_tier(&self) -> u8 {
        let health = self.health_score.clamp(0.0, 1.0);
        if health >= 0.9 {
            0
        } else if health >= 0.7 {
            1
        } else if health >= 0.5 {
            2
        } else if health >= 0.25 {
            3
        } else {
            4
        }
    }

    /// Latency band width, in milliseconds.
    ///
    /// Keys within one band are treated as equally fast, so load is shared
    /// between them by capacity instead of all of it going to whichever is
    /// marginally quicker. Without this, `least_latency` pinned ~93% of traffic
    /// to one key and spent the rest retrying off exhausted keys.
    const LATENCY_BAND_MS: f64 = 100.0;

    /// Rank for `least_latency`: explore, then prefer the fastest band that is
    /// not saturated.
    ///
    /// Ordering is deliberate:
    ///
    /// 1. an unmeasured key sorts first, so every key is tried before any is
    ///    judged (treating "unmeasured" as "infinitely slow" starved the pool);
    /// 2. then the latency band, so a clearly faster key is genuinely preferred;
    /// 3. then utilisation, so within a band the emptier key wins. This is what
    ///    stops the fastest key from absorbing every request until its quota is
    ///    gone and the broker has to rotate off a 429.
    fn latency_rank(&self) -> (u8, u32, u32) {
        match self.latency_ms {
            // 0 sorts before 1: unmeasured keys are explored first.
            None => (0, 0, 0),
            Some(latency) => {
                let band = if latency.is_finite() && latency > 0.0 {
                    (latency / Self::LATENCY_BAND_MS).floor() as u32
                } else {
                    u32::MAX
                };
                // Utilisation as a permille, so it orders as an integer and
                // near-equal values tie exactly (letting `best_by` rotate).
                let utilisation = (self.utilisation().clamp(0.0, 1.0) * 1000.0) as u32;
                (1, band, utilisation)
            }
        }
    }
}

/// Deterministic counter shared by the round-robin family of strategies.
#[derive(Debug, Default)]
pub struct RotationCounter(std::sync::atomic::AtomicU64);

impl RotationCounter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

/// Choose one candidate index. `candidates` is never empty.
pub fn select(
    strategy: Strategy,
    candidates: &[Candidate],
    counter: &RotationCounter,
    tolerance: f64,
) -> usize {
    debug_assert!(!candidates.is_empty());
    if candidates.len() == 1 {
        return candidates[0].index;
    }

    match strategy {
        Strategy::RoundRobin => {
            let start = counter.next() as usize % candidates.len();
            candidates[start].index
        }
        Strategy::WeightedRandom => weighted_pick(candidates, tolerance, true),
        // The "least X" strategies all rank by one score, then rotate across
        // the candidates tied for the best score. Plain `min_by` returns the
        // first candidate on a tie, which pinned every request to the same key
        // while a fresh pool sits at identical utilisation.
        Strategy::LeastBusy => best_by(candidates, counter, |c| {
            // In-flight first, *lexicographically*, then a coarse health tier.
            //
            // The bug this replaces: health was folded into the same number as
            // in-flight (`in_flight - health * 1e-9`). Health is quantised, so
            // two idle keys differed by a real amount, `best_by` saw no tie,
            // rotation never ran, and every request went to the marginally
            // healthiest key -- measured at 2/25/3 over three runs.
            //
            // Tiering rather than scaling is deliberate. A 0.1% health
            // difference must not send all load to one key: only a genuinely
            // degraded key should be avoided, and in-flight remains the
            // dominant signal.
            (c.in_flight, c.health_tier())
        }),
        Strategy::LeastLatency => best_by(candidates, counter, |c| c.latency_rank()),
        Strategy::UsageBased => best_by(candidates, counter, |c| {
            // Utilisation dominates; in-flight breaks near-ties.
            c.utilisation() + c.in_flight as f64 * 1e-9
        }),
        Strategy::PowerOfTwo => {
            let mut first = pick_random(candidates);
            let mut second = pick_random(candidates);
            if candidates.len() > 1 {
                while second == first {
                    second = pick_random(candidates);
                }
            }
            let a = &candidates[first];
            let b = &candidates[second];
            first = if a.effective_weight() >= b.effective_weight() {
                first
            } else {
                second
            };
            candidates[first].index
        }
        Strategy::Fallback => candidates[0].index,
    }
}

/// Pick the candidate with the lowest `score`, spreading across ties.
///
/// A plain minimum would always return the first candidate, which collapses a
/// pool of equally-idle keys onto one key. Ties are resolved by rotating
/// through them, so "least busy" also means "evenly spread".
/// A score that can be compared and told apart from a near-equal one.
///
/// A single `f64` cannot carry two decisions. `least_latency` needs "has this
/// key been measured at all?" *and* "how fast was it?", and folding them into
/// one float is how it came to pin all traffic on one key. A tuple orders
/// lexicographically, which is exactly the intent.
pub trait Score: Copy + PartialOrd {
    /// The largest value, so the comparison starts from the worst possible.
    fn worst() -> Self;
    /// Whether two scores are close enough to call a tie.
    ///
    /// The tolerance must be *smaller* than the smallest difference the caller
    /// cares about, or a real difference is treated as a tie and the tie-break
    /// rotation silently stops working.
    fn is_tie(self, other: Self) -> bool;
}

impl Score for f64 {
    fn worst() -> Self {
        f64::INFINITY
    }

    fn is_tie(self, other: Self) -> bool {
        (self - other).abs() <= 1e-9
    }
}

impl Score for (u32, u8) {
    fn worst() -> Self {
        (u32::MAX, u8::MAX)
    }

    fn is_tie(self, other: Self) -> bool {
        self == other
    }
}

impl Score for (u8, u32, u32) {
    fn worst() -> Self {
        (u8::MAX, u32::MAX, u32::MAX)
    }

    fn is_tie(self, other: Self) -> bool {
        self == other
    }
}

impl Score for (u8, f64) {
    fn worst() -> Self {
        (u8::MAX, f64::INFINITY)
    }

    fn is_tie(self, other: Self) -> bool {
        // The flag is exact; the value uses the float tolerance.
        self.0 == other.0 && (self.1 - other.1).abs() <= 1e-9
    }
}

/// Pick the lowest score, rotating among ties so identical keys share load.
fn best_by<S: Score>(
    candidates: &[Candidate],
    counter: &RotationCounter,
    score: impl Fn(&Candidate) -> S,
) -> usize {
    let mut best = S::worst();
    let mut tied: Vec<usize> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let value = score(candidate);
        if value.is_tie(best) {
            tied.push(candidate.index);
        } else if value < best {
            best = value;
            tied.clear();
            tied.push(candidate.index);
        }
    }
    if tied.is_empty() {
        return candidates[0].index;
    }
    tied[(counter.next() as usize) % tied.len()]
}

/// Weighted random selection that tolerates small weight differences.
///
/// With `tolerance > 0` a lighter key can still win the roll, which keeps a
/// pool of identical keys from serialising onto a single favourite.
fn weighted_pick(candidates: &[Candidate], tolerance: f64, use_effective: bool) -> usize {
    let weights: Vec<f64> = candidates
        .iter()
        .map(|c| {
            if use_effective {
                c.effective_weight()
            } else {
                f64::from(c.weight).max(1e-3)
            }
        })
        .collect();
    let total: f64 = weights.iter().sum();
    if !(total.is_finite() && total > 0.0) {
        return candidates[0].index;
    }

    let tolerance = tolerance.clamp(0.0, 1.0);
    let mut roll = rand_unit() * total;

    // Randomly relax the ordering so near-equal weights shuffle.
    if tolerance > 0.0 {
        roll *= 1.0 + tolerance * (rand_unit() - 0.5) * 2.0;
    }

    let mut cursor = 0.0;
    for (position, weight) in weights.iter().enumerate() {
        cursor += weight;
        if roll < cursor {
            return candidates[position].index;
        }
    }
    // Floating point fall-through: pick the heaviest.
    weights
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(position, _)| candidates[position].index)
        .unwrap_or(candidates[0].index)
}

fn pick_random(candidates: &[Candidate]) -> usize {
    let roll = rand_unit();
    ((roll * candidates.len() as f64) as usize).min(candidates.len() - 1)
}

/// Convert a `Retry-After` header value into a duration.
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let trimmed = value.trim();
    // Seconds form is what LLM providers send; the HTTP-date form is rare and
    // falling back to the configured cooldown is safe.
    trimmed.parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(index: usize, in_flight: u32, weight: u32, latency: Option<f64>) -> Candidate {
        Candidate {
            index,
            in_flight,
            weight,
            latency_ms: latency,
            rpm: 0,
            tpm: 0,
            max_rpm: None,
            max_tpm: None,
            health_score: 1.0,
        }
    }

    #[test]
    fn parse_accepts_legacy_and_new_names() {
        assert_eq!(Strategy::parse("round_robin"), Some(Strategy::RoundRobin));
        assert_eq!(Strategy::parse("Round-Robin"), Some(Strategy::RoundRobin));
        assert_eq!(
            Strategy::parse("latency_based"),
            Some(Strategy::LeastLatency)
        );
        assert_eq!(Strategy::parse("least_used"), Some(Strategy::LeastBusy));
        assert_eq!(
            Strategy::parse("usage-based-routing"),
            Some(Strategy::UsageBased)
        );
        assert_eq!(Strategy::parse("nope"), None);
    }

    #[test]
    fn round_robin_cycles_in_order() {
        let candidates = vec![
            candidate(0, 0, 1, None),
            candidate(1, 0, 1, None),
            candidate(2, 0, 1, None),
        ];
        let counter = RotationCounter::new();
        let picked: Vec<usize> = (0..4)
            .map(|_| select(Strategy::RoundRobin, &candidates, &counter, 0.0))
            .collect();
        assert_eq!(picked, vec![0, 1, 2, 0]);
    }

    #[test]
    fn least_busy_prefers_the_idle_key() {
        let candidates = vec![
            candidate(0, 5, 1, Some(10.0)),
            candidate(1, 0, 1, Some(500.0)),
            candidate(2, 3, 1, Some(10.0)),
        ];
        let picked = select(
            Strategy::LeastBusy,
            &candidates,
            &RotationCounter::new(),
            0.0,
        );
        assert_eq!(picked, 1);
    }

    #[test]
    fn least_latency_prefers_the_fastest_once_everything_is_measured() {
        let candidates = vec![
            candidate(0, 0, 1, Some(120.0)),
            candidate(1, 0, 1, Some(45.0)),
        ];
        let picked = select(
            Strategy::LeastLatency,
            &candidates,
            &RotationCounter::new(),
            0.0,
        );
        assert_eq!(picked, 1, "the fastest measured key wins");
    }

    #[test]
    fn least_latency_explores_an_unmeasured_key_before_judging_it() {
        // This test previously asserted the opposite ("an unmeasured key must
        // not win on latency"), which is what pinned every request to the first
        // key ever measured: measured at 30/0/0 over three runs.
        //
        // A key with no measurement has not been shown to be slow, and choosing
        // it is the only way to find out. `best_by` rotates among ties, so
        // several unmeasured keys are visited in turn.
        let unmeasured = vec![candidate(0, 0, 1, Some(120.0)), candidate(1, 0, 1, None)];
        let picked = select(
            Strategy::LeastLatency,
            &unmeasured,
            &RotationCounter::new(),
            0.0,
        );
        assert_eq!(picked, 1, "the unmeasured key should be tried");

        // With two unmeasured keys they alternate, rather than both being
        // starved behind a measured one.
        let two_unmeasured = vec![
            candidate(0, 0, 1, Some(10.0)),
            candidate(1, 0, 1, None),
            candidate(2, 0, 1, None),
        ];
        let counter = RotationCounter::new();
        let seen: Vec<usize> = (0..4)
            .map(|_| select(Strategy::LeastLatency, &two_unmeasured, &counter, 0.0))
            .collect();
        assert!(seen.contains(&1) && seen.contains(&2), "saw {seen:?}");
        assert!(
            !seen.contains(&0),
            "the measured key waits its turn: {seen:?}"
        );
    }

    #[test]
    fn least_latency_still_prefers_a_measured_key_over_a_slow_one() {
        // Exploration must not defeat the purpose: once every key is measured,
        // the slow ones lose.
        let candidates = vec![
            candidate(0, 0, 1, Some(900.0)),
            candidate(1, 0, 1, Some(20.0)),
            candidate(2, 0, 1, Some(500.0)),
        ];
        for _ in 0..5 {
            assert_eq!(
                select(
                    Strategy::LeastLatency,
                    &candidates,
                    &RotationCounter::new(),
                    0.0
                ),
                1
            );
        }
    }

    #[test]
    fn usage_based_picks_the_least_utilised() {
        let mut busy = candidate(0, 0, 1, None);
        busy.rpm = 90;
        busy.max_rpm = Some(100);
        let mut idle = candidate(1, 0, 1, None);
        idle.rpm = 5;
        idle.max_rpm = Some(100);
        let picked = select(
            Strategy::UsageBased,
            &[busy, idle],
            &RotationCounter::new(),
            0.0,
        );
        assert_eq!(picked, 1);
    }

    #[test]
    fn least_busy_spreads_across_equally_idle_keys() {
        // Regression: `min_by` returned the first candidate, so a fresh pool
        // sent every request to the same key even under least_busy.
        let candidates = vec![
            candidate(0, 0, 1, None),
            candidate(1, 0, 1, None),
            candidate(2, 0, 1, None),
        ];
        let counter = RotationCounter::new();
        let picked: Vec<usize> = (0..6)
            .map(|_| select(Strategy::LeastBusy, &candidates, &counter, 0.0))
            .collect();
        assert_eq!(picked, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn least_busy_spreads_across_idle_keys_with_different_health() {
        // The measured bug. All three keys are idle, but health is quantised --
        // one failure in a pool of three moves it by a whole step -- so the
        // keys do *not* score identically. With health scaled at 1e-9 the term
        // was ~1e-12, larger than `best_by`'s tolerance, so "equal" keys were
        // never tied, rotation never ran, and traffic pinned to one key.
        //
        // Live measurement before the fix: 2/25/3, 1/26/3, 2/24/4 over three
        // runs of 30 requests. Now the tie is real and they rotate.
        let mut candidates = vec![
            candidate(0, 0, 1, None),
            candidate(1, 0, 1, None),
            candidate(2, 0, 1, None),
        ];
        candidates[0].health_score = 1.0;
        candidates[1].health_score = 0.999;
        candidates[2].health_score = 0.998;

        let counter = RotationCounter::new();
        let mut counts = [0usize; 3];
        for _ in 0..30 {
            let picked = select(Strategy::LeastBusy, &candidates, &counter, 0.0);
            counts[picked] += 1;
        }
        assert_eq!(
            counts,
            [10, 10, 10],
            "a healthy pool must share load regardless of tie-break health"
        );
    }

    #[test]
    fn least_busy_still_avoids_a_genuinely_unhealthy_key() {
        // Tiering must not blunt the strategy: a degraded key has to lose to an
        // idle, healthy one.
        let mut candidates = vec![candidate(0, 0, 1, None), candidate(1, 0, 1, None)];
        candidates[0].health_score = 0.4; // tier 3
        candidates[1].health_score = 1.0; // tier 0

        let counter = RotationCounter::new();
        for _ in 0..6 {
            assert_eq!(
                select(Strategy::LeastBusy, &candidates, &counter, 0.0),
                1,
                "the degraded key must not receive traffic"
            );
        }
    }

    #[test]
    fn usage_based_spreads_across_equally_utilised_keys() {
        // Regression: observed live -- seven requests all landed on key1 when
        // every key reported zero utilisation.
        let candidates = vec![
            candidate(0, 0, 1, None),
            candidate(1, 0, 1, None),
            candidate(2, 0, 1, None),
        ];
        let counter = RotationCounter::new();
        let picked: Vec<usize> = (0..6)
            .map(|_| select(Strategy::UsageBased, &candidates, &counter, 0.0))
            .collect();
        assert_eq!(picked, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn least_latency_spreads_when_measurements_are_identical() {
        let candidates = vec![
            candidate(0, 0, 1, Some(50.0)),
            candidate(1, 0, 1, Some(50.0)),
        ];
        let counter = RotationCounter::new();
        let picked: Vec<usize> = (0..4)
            .map(|_| select(Strategy::LeastLatency, &candidates, &counter, 0.0))
            .collect();
        assert_eq!(picked, vec![0, 1, 0, 1]);
    }

    #[test]
    fn ties_are_only_broken_among_the_best_candidates() {
        // A clearly better candidate must win regardless of rotation.
        let candidates = vec![
            candidate(0, 5, 1, None),
            candidate(1, 0, 1, None),
            candidate(2, 0, 1, None),
        ];
        let counter = RotationCounter::new();
        let picked: Vec<usize> = (0..4)
            .map(|_| select(Strategy::LeastBusy, &candidates, &counter, 0.0))
            .collect();
        assert_eq!(picked, vec![1, 2, 1, 2], "key 0 is never tied for best");
    }

    #[test]
    fn fallback_always_prefers_the_first_candidate() {
        let candidates = vec![
            candidate(0, 9, 1, Some(900.0)),
            candidate(1, 0, 1, Some(1.0)),
        ];
        for _ in 0..10 {
            assert_eq!(
                select(
                    Strategy::Fallback,
                    &candidates,
                    &RotationCounter::new(),
                    0.0
                ),
                0
            );
        }
    }

    #[test]
    fn on_cooldown_keys_are_never_candidates() {
        // The pool filters before selecting; this guards the invariant that a
        // single candidate is returned unchanged.
        let candidates = vec![candidate(7, 0, 1, None)];
        assert_eq!(
            select(
                Strategy::LeastBusy,
                &candidates,
                &RotationCounter::new(),
                0.0
            ),
            7
        );
    }

    #[test]
    fn weighted_random_respects_weights_over_many_draws() {
        let candidates = vec![candidate(0, 0, 9, None), candidate(1, 0, 1, None)];
        let counter = RotationCounter::new();
        let mut heavy = 0;
        for _ in 0..1_000 {
            if select(Strategy::WeightedRandom, &candidates, &counter, 0.0) == 0 {
                heavy += 1;
            }
        }
        assert!(heavy > 820 && heavy < 980, "heavy key won {heavy}/1000");
    }

    #[test]
    fn effective_weight_drops_with_utilisation() {
        let mut loaded = candidate(0, 0, 10, None);
        loaded.rpm = 100;
        loaded.max_rpm = Some(100);
        let fresh = candidate(1, 0, 1, None);
        assert!(
            fresh.effective_weight() > loaded.effective_weight(),
            "an exhausted key must not outweigh an idle one"
        );
    }

    #[test]
    fn retry_after_parses_seconds() {
        assert_eq!(parse_retry_after("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_retry_after(" 12 "), Some(Duration::from_secs(12)));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
    }
}
