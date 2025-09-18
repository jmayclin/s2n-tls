use std::time::{Duration, SystemTime};

use crate::EPOCH_DURATION;

pub fn current_epoch() -> u64 {
    // SAFETY: this method will panic if the current system clock is set to
    // a time before the unix epoch. This is not a recoverable error, so we
    // panic
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("expected system time to be after UNIX epoch");
    now.as_secs() / (3_600 * 24)
}

/// Return the instant in time that `key_epoch` starts
pub fn epoch_start(key_epoch: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + (EPOCH_DURATION * (key_epoch as u32))
}

/// The Duration between now and the start of key_epoch
///
/// returns None if the epoch has already started
pub fn until_epoch_start(key_epoch: u64) -> Option<Duration> {
    epoch_start(key_epoch)
        .duration_since(SystemTime::now())
        .ok()
}

/// The Duration between now and when the actor should make the network call
/// to KMS to retrieve the secret from key_epoch.
///
/// returns None if the fetch should already have occurred
pub(crate) fn until_fetch(key_epoch: u64, kms_smoothing_factor: u32) -> Option<Duration> {
    // we always want to fetch the key at least one epoch (24 hours) before the
    // key is needed.
    let fetch_time = {
        let fetch_epoch = key_epoch - 2;

        let fetch_epoch_start = epoch_start(fetch_epoch);

        fetch_epoch_start + Duration::from_secs(kms_smoothing_factor as u64)
    };

    fetch_time.duration_since(SystemTime::now()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current() {
        let current_epoch = current_epoch();
        let start = epoch_start(current_epoch);
        assert!(SystemTime::now().duration_since(start).is_ok());
        let future_start = epoch_start(current_epoch + 2);
        assert!(future_start.duration_since(SystemTime::now()).is_ok());
    }

    #[test]
    fn until_start() {
        let current = current_epoch();
        // epoch start was in the past, and should return none
        assert!(until_epoch_start(current).is_none());
        assert!(until_epoch_start(current + 2).is_some());
    }

    #[test]
    fn fetch() {
        let current_epoch = current_epoch();
        assert!(until_fetch(current_epoch, 0).is_none());
        assert!(until_fetch(current_epoch + 1, 0).is_none());
        // This test could be flaky, because if called on the epoch boundary, the
        // last line might return none.
        // Flakiness Probability:
        //     test runtime: 27.48 us -> window of "flaky"
        //     probability = 27.48 us / 24 hr
        //     approximately 1 / 3_200_000_000
        // So if we ran the test 1,000 times a day it would fail about once every
        // 1,000 years
        assert!(until_fetch(current_epoch + 2, 0).is_none());
        assert!(until_fetch(current_epoch + 2, 24 * 3_600).is_some());
    }
}
