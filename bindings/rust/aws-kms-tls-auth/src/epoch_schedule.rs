use std::time::{Duration, SystemTime};

use crate::KEY_ROTATION_PERIOD;

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
fn epoch_start(key_epoch: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + (KEY_ROTATION_PERIOD * (key_epoch as u32))
}

/// The Duration between now and the start of key_epoch
///
/// returns None if the epoch has already started
fn until_epoch_start(key_epoch: u64) -> Option<Duration> {
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
        let fetch_time = fetch_epoch_start + Duration::from_secs(kms_smoothing_factor as u64);
        fetch_time
    };

    fetch_time.duration_since(SystemTime::now()).ok()
}
