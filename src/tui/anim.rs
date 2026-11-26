use std::time::{Duration, Instant};

pub const FRAME: Duration = Duration::from_millis(33);
pub const SPIN: Duration = Duration::from_millis(100);
pub const SPIN_IDLE: Duration = Duration::from_millis(500);
pub const IDLE_AFTER: Duration = Duration::from_secs(30);
pub const TRANSITION: Duration = Duration::from_millis(360);
pub const TWEEN: Duration = Duration::from_millis(450);
pub const PULSE: Duration = Duration::from_millis(1200);
pub const NOTICE_FADE_MS: u64 = 1000;
pub const SAMPLE: Duration = Duration::from_secs(1);
pub const HISTORY: usize = 30;

pub const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
pub const SPARK: [&str; 8] = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];
pub const EIGHTHS: [&str; 8] = ["▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"];

pub fn progress(start: Instant, now: Instant, dur: Duration) -> f32 {
    let e = now.saturating_duration_since(start).as_secs_f32();
    (e / dur.as_secs_f32()).clamp(0.0, 1.0)
}

pub fn ease_out(p: f32) -> f32 {
    let q = 1.0 - p.clamp(0.0, 1.0);
    1.0 - q * q * q
}

pub fn smooth(p: f32) -> f32 {
    let p = p.clamp(0.0, 1.0);
    p * p * (3.0 - 2.0 * p)
}

// a flash that fades out with two soft beats
pub fn pulse(p: f32) -> f32 {
    let p = p.clamp(0.0, 1.0);
    let beat = 0.5 - 0.5 * (p * std::f32::consts::TAU * 2.0).cos();
    (beat * (1.0 - p)).clamp(0.0, 1.0)
}

// steady breathing in 0..1 with a 1.6 s period
pub fn breathe(epoch: Instant, now: Instant) -> f32 {
    let s = now.saturating_duration_since(epoch).as_secs_f32();
    0.5 - 0.5 * (s / 1.6 * std::f32::consts::TAU).cos()
}

pub fn spin_index(epoch: Instant, now: Instant, period: Duration) -> usize {
    let n = now.saturating_duration_since(epoch).as_millis() / period.as_millis().max(1);
    (n % SPINNER.len() as u128) as usize
}

pub fn next_spin(epoch: Instant, now: Instant, period: Duration) -> Instant {
    let step = period.as_nanos().max(1);
    let e = now.saturating_duration_since(epoch).as_nanos();
    let next = (e / step + 1) * step;
    epoch + Duration::from_nanos(u64::try_from(next).unwrap_or(u64::MAX))
}

#[derive(Clone, Copy, Debug)]
pub struct Tween {
    from: f64,
    to: f64,
    start: Instant,
    dur: Duration,
}

impl Tween {
    pub fn new(v: f64, now: Instant) -> Self {
        Self {
            from: v,
            to: v,
            start: now,
            dur: TWEEN,
        }
    }

    pub fn set(&mut self, to: f64, now: Instant) {
        if to != self.to {
            self.from = self.value(now);
            self.to = to;
            self.start = now;
        }
    }

    pub fn value(&self, now: Instant) -> f64 {
        let p = f64::from(ease_out(progress(self.start, now, self.dur)));
        self.from + (self.to - self.from) * p
    }

    pub fn moving(&self, now: Instant) -> bool {
        self.from != self.to && now < self.start + self.dur
    }
}

#[derive(Clone, Debug)]
pub struct Hist {
    buf: [f32; HISTORY],
    head: usize,
    len: usize,
}

impl Default for Hist {
    fn default() -> Self {
        Self {
            buf: [0.0; HISTORY],
            head: 0,
            len: 0,
        }
    }
}

impl Hist {
    pub fn push(&mut self, v: f32) {
        self.buf[self.head] = v;
        self.head = (self.head + 1) % HISTORY;
        self.len = (self.len + 1).min(HISTORY);
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    // oldest to newest
    pub fn get(&self, i: usize) -> f32 {
        let start = (self.head + HISTORY - self.len) % HISTORY;
        self.buf[(start + i) % HISTORY]
    }

    pub fn last(&self) -> f32 {
        if self.is_empty() {
            0.0
        } else {
            self.get(self.len - 1)
        }
    }

    pub fn max(&self) -> f32 {
        (0..self.len).map(|i| self.get(i)).fold(0.0, f32::max)
    }

    pub fn any(&self) -> bool {
        (0..self.len).any(|i| self.get(i) > 0.0)
    }
}

pub fn spark_level(v: f32, max: f32) -> Option<usize> {
    if v <= 0.0 || max <= 0.0 {
        return None;
    }
    Some((((v / max) * 8.0).ceil() as usize).clamp(1, 8) - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easing_is_bounded_and_monotone() {
        let mut prev = (0.0f32, 0.0f32);
        for i in -10..=110 {
            let p = i as f32 / 100.0;
            let (e, s) = (ease_out(p), smooth(p));
            assert!((0.0..=1.0).contains(&e) && (0.0..=1.0).contains(&s), "{p}");
            assert!(e >= prev.0 && s >= prev.1, "{p}");
            assert!((0.0..=1.0).contains(&pulse(p)));
            prev = (e, s);
        }
        assert_eq!((ease_out(0.0), ease_out(1.0)), (0.0, 1.0));
        assert_eq!((smooth(0.0), smooth(1.0)), (0.0, 1.0));
        assert_eq!((pulse(0.0), pulse(1.0)), (0.0, 0.0));
    }

    #[test]
    fn tween_retargets_from_current_value_and_settles() {
        let t0 = Instant::now();
        let mut tw = Tween::new(10.0, t0);
        assert!(!tw.moving(t0));
        tw.set(110.0, t0);
        let mid = tw.value(t0 + TWEEN / 2);
        assert!(mid > 10.0 && mid < 110.0, "{mid}");
        assert!(tw.moving(t0 + TWEEN / 2));
        tw.set(0.0, t0 + TWEEN / 2);
        let v = tw.value(t0 + TWEEN / 2);
        assert!((v - mid).abs() < 1e-9, "jumped from {mid} to {v}");
        for ms in 0..2000 {
            let x = tw.value(t0 + Duration::from_millis(ms));
            assert!((0.0..=110.0).contains(&x), "{x}");
        }
        assert_eq!(tw.value(t0 + TWEEN * 2), 0.0);
        assert!(!tw.moving(t0 + TWEEN * 2));
    }

    #[test]
    fn spinner_deadline_lands_on_the_next_step() {
        let e = Instant::now();
        let n = next_spin(e, e + Duration::from_millis(101), SPIN);
        assert_eq!(n, e + SPIN * 2);
        assert_eq!(spin_index(e, n, SPIN), 2);
        assert_eq!(spin_index(e, e + SPIN * 10, SPIN), 0);
        assert_eq!(next_spin(e, e + SPIN, SPIN_IDLE), e + SPIN_IDLE);
    }

    #[test]
    fn history_keeps_the_newest_samples_in_order() {
        let mut h = Hist::default();
        assert!(!h.any());
        for i in 0..(HISTORY + 5) {
            h.push(i as f32);
        }
        assert_eq!(h.len(), HISTORY);
        assert_eq!(h.get(0), 5.0);
        assert_eq!(h.last(), (HISTORY + 4) as f32);
        assert_eq!(spark_level(0.0, 9.0), None);
        assert_eq!(spark_level(9.0, 9.0), Some(7));
        assert_eq!(spark_level(0.01, 9.0), Some(0));
    }
}
