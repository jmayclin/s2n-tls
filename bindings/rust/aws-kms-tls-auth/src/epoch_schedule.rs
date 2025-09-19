// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The key epochs and fetching behavior are designed to accomplish the following
//! goals:
//! Requirement 1: if fetching new keys fails, there should be at least 24 before
//! handshakes actually start failing.
//! Requirement 2: traffic to KMS should be smooth, avoiding any spikes at e.g.
//! the top of the hour.
//!
//! ```text
//! Epoch
//! 0     1     2     3     4
//! |-----|-----|-----|-----|
//!                   ^
//!                   epoch 3 start
//!```
//!
//! To satisfy these requirements, we fetch the key for epoch `n` during epoch
//! `n - 2`. Each peer adds [0, 24 * 3600) seconds of delay to smooth out traffic
//! to KMS.
//!
//! ```text
//! Epoch
//! 0     1     2     3     4
//! |-----|-----|-----|-----|
//!       ++++++      ^
//!          ^        epoch 3 start
//!          |
//!        fetch window for epoch 3   
//! ```

use std::time::{Duration, SystemTime};

use rand::Rng;

use crate::EPOCH_DURATION;

/// Return a "smoothing factor" indicating how long the actor should wait before
/// fetching the key for some epoch
pub fn kms_smoothing_factor() -> Duration {
    rand::rng().random_range(Duration::from_secs(0)..EPOCH_DURATION)
}

pub fn current_epoch() -> u64 {
    // SAFETY: this method will panic if the current system clock is set to
    // a time before the unix epoch. This is not a recoverable error, so we
    // panic
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("expected system time to be after UNIX epoch");
    now.as_secs() / (EPOCH_DURATION.as_secs())
}

/// Return the instant in time that `epoch` starts
pub fn epoch_start(epoch: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + (EPOCH_DURATION * (epoch as u32))
}

/// The Duration between now and the start of epoch
///
/// returns None if the epoch has already started
pub fn until_epoch_start(epoch: u64) -> Option<Duration> {
    epoch_start(epoch).duration_since(SystemTime::now()).ok()
}

/// The Duration between now and when the actor should make the network call
/// to KMS to retrieve the secret for `epoch`.
///
/// returns None if the fetch should already have occurred
pub(crate) fn until_fetch(epoch: u64, kms_smoothing_factor: Duration) -> Option<Duration> {
    // we always want to fetch the key at least one epoch (24 hours) before the
    // key is needed.
    let fetch_time = {
        let fetch_epoch = epoch - 2;

        let fetch_epoch_start = epoch_start(fetch_epoch);

        fetch_epoch_start + kms_smoothing_factor
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
        let future_start = epoch_start(current_epoch + 1);
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
        const ZERO_DURATION: Duration = Duration::from_secs(0);
        
        let current_epoch = current_epoch();
        assert!(until_fetch(current_epoch, ZERO_DURATION).is_none());
        assert!(until_fetch(current_epoch + 1, ZERO_DURATION).is_none());
        // This test could be flaky, because if called on the epoch boundary, the
        // last line might return none.
        // Flakiness Probability:
        //     test runtime: 27.48 us -> window of "flaky"
        //     probability = 27.48 us / 24 hr
        //     approximately 1 / 3_200_000_000
        // So if we ran the test 1,000 times a day it would fail about once every
        // 1,000 years
        assert!(until_fetch(current_epoch + 2, ZERO_DURATION).is_none());
        assert!(until_fetch(current_epoch + 2, EPOCH_DURATION).is_some());
    }
}
