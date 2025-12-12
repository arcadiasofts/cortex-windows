use super::error::RecordError;
use std::time::{SystemTime, UNIX_EPOCH};

include!(concat!(env!("OUT_DIR"), "/cortex.rs"));

const EXPIRATION_TIME: i64 = 604_800;

impl BeaconRecord {
    pub fn verify(&self) -> Result<(), RecordError> {
        // --- Verify Timestamp ---
        let now_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;
        
        let time_diff = now_time - self.timestamp;

        if time_diff > EXPIRATION_TIME {
            return Err(RecordError::Expired);
        } else if time_diff < 0 {
            return Err(RecordError::FutureTimestamp);
        }

        // --- Verify Signature ---
        // TODO: Add signature verify logic

        Ok(())
    }
}
