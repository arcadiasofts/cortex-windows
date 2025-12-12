use std::{fmt, time::SystemTimeError};

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("TXT record parsing failed: {0}")]
    ParseError(String),
    #[error("TXT record verification failed: {0}")]
    VerificationError(String),
    #[error("resolver error: {0}")]
    ResolverError(String),
}

impl DnsError {
    pub fn parse(msg: impl fmt::Display) -> Self {
        DnsError::ParseError(msg.to_string())
    }

    pub fn verify(msg: impl fmt::Display) -> Self {
        DnsError::VerificationError(msg.to_string())
    }

    pub fn resolver(msg: impl fmt::Display) -> Self {
        DnsError::ResolverError(msg.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    #[error("Kademlia query failed: {0}")]
    QueryError(String),
    #[error("transport error: {0}")]
    TransportError(String),
    #[error("bootstrap error: {0}")]
    BootstrapError(String),
}

impl DhtError {
    pub fn query(msg: impl fmt::Display) -> Self {
        DhtError::QueryError(msg.to_string())
    }

    pub fn transport(msg: impl fmt::Display) -> Self {
        DhtError::TransportError(msg.to_string())
    }

    pub fn bootstrap(msg: impl fmt::Display) -> Self {
        DhtError::BootstrapError(msg.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("system clock error: {0}")]
    Clock(#[from] SystemTimeError),
    #[error("beacon record expired")]
    Expired,
    #[error("beacon record timestamp is in the future")]
    FutureTimestamp,
    #[error("signature verification not implemented")]
    SignatureNotImplemented,
}
