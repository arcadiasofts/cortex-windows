use crate::cortex_beacon::{error::DnsError, record::BeaconRecord};
use base64::{engine::general_purpose, Engine as _};
use hickory_resolver::{config::ResolverConfig, name_server::TokioConnectionProvider, Resolver};
use std::iter;

pub async fn resolve_dns(domain: &str) -> Result<Option<BeaconRecord>, DnsError> {
    let resolver = Resolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build();

    let query_domain = format!("_cortex_beacon.{}", domain);

    match resolver.txt_lookup(query_domain).await {
        Ok(records) => {
            for record in records.iter() {
                let record_str = assemble_txt_record(record.txt_data());

                for candidate in try_decode_base64(&record_str)
                    .into_iter()
                    .chain(iter::once(record_str))
                {
                    if let Ok(parsed) = parse_txt_record(&candidate) {
                        return Ok(Some(parsed));
                    }
                }
            }
            Ok(None)
        }
        Err(err) => Err(DnsError::resolver(err)),
    }
}

#[inline(always)]
fn assemble_txt_record(chunks: &[Box<[u8]>]) -> String {
    let total_len: usize = chunks.iter().map(|chunk| chunk.len()).sum();
    let mut combined = String::with_capacity(total_len);

    for chunk in chunks {
        let decoded = String::from_utf8_lossy(chunk);
        combined.push_str(decoded.as_ref());
    }

    combined
}

#[inline(always)]
fn try_decode_base64(input: &str) -> Option<String> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return None;
    }

    let decoded = general_purpose::STANDARD.decode(trimmed).ok()?;
    String::from_utf8(decoded).ok()
}

#[inline(always)]
fn parse_txt_record(txt: &str) -> Result<BeaconRecord, DnsError> {
    let mut current_url: Option<String> = None;
    let mut timestamp: Option<i64> = None;
    let mut signature: Option<Vec<u8>> = None;

    for token in txt.split(';') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        match token.split_once('=') {
            Some(("v", _)) => continue,
            Some(("url", rest)) => {
                let trimmed = rest.trim();
                if trimmed.is_empty() || !trimmed.contains("://") {
                    return Err(DnsError::parse("invalid url field"));
                }
                current_url = Some(trimmed.to_string());
            }
            Some(("ts", rest)) => {
                let parsed = rest
                    .parse::<i64>()
                    .map_err(|_| DnsError::parse("invalid timestamp field"))?;
                if parsed <= 0 {
                    return Err(DnsError::parse("non-positive timestamp value"));
                }
                timestamp = Some(parsed);
            }
            Some(("sig", rest)) => {
                let decoded = general_purpose::STANDARD
                    .decode(rest.trim())
                    .map_err(|_| DnsError::parse("invalid signature field"))?;
                signature = Some(decoded);
            }
            _ => {}
        }
    }

    let guild_id = String::new(); // TODO: guild_id should be provided externally

    let record = BeaconRecord {
        guild_id,
        current_url: current_url.ok_or_else(|| DnsError::parse("missing url field"))?,
        timestamp: timestamp.ok_or_else(|| DnsError::parse("missing timestamp field"))?,
        signature: signature.ok_or_else(|| DnsError::parse("missing signature field"))?,
    };

    record
        .verify()
        .map_err(|err| DnsError::verify(err.to_string()))?;

    Ok(record)
}
