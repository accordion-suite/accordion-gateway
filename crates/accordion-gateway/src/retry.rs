//! Waiting longer after each failure, so a broken setup doesn't hammer a
//! provider's API.

use std::time::Duration;

/// `first` after one failure, twice as long after each one after that, and
/// never more than `max`.
pub(crate) fn delay(failures: u32, first: Duration, max: Duration) -> Duration {
    let factor = 1u32
        .checked_shl(failures.saturating_sub(1))
        .unwrap_or(u32::MAX);
    first.saturating_mul(factor).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_up_to_the_limit() {
        let minutes = |failures| {
            delay(
                failures,
                Duration::from_secs(15 * 60),
                Duration::from_secs(12 * 60 * 60),
            )
            .as_secs()
                / 60
        };
        assert_eq!(minutes(1), 15);
        assert_eq!(minutes(2), 30);
        assert_eq!(minutes(3), 60);
        assert_eq!(minutes(7), 12 * 60);
        assert_eq!(minutes(100), 12 * 60);
    }
}
