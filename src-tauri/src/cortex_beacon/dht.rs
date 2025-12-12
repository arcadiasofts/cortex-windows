use super::{error::DhtError, record::BeaconRecord};
use futures::StreamExt;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    identity,
    kad::{
        store::MemoryStore, Behaviour as KadBehaviour, Event as KadEvent, GetRecordOk, QueryId,
        QueryResult, RecordKey,
    },
    noise, tcp, yamux, PeerId, Swarm, SwarmBuilder, Transport,
    swarm::SwarmEvent,
};
use prost::Message;
use std::error::Error;
use tokio::time::{timeout, Duration};

const DHT_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn search_node(
    guild_id: &str,
    keypair: identity::Keypair,
) -> Result<Option<BeaconRecord>, DhtError> {
    let mut swarm = create_swarm(keypair)?;

    let target_key = RecordKey::new(&format!("/cortex/beacon/{guild_id}"));
    let query_id = swarm.behaviour_mut().get_record(target_key);

    await_query_result(&mut swarm, query_id).await
}

fn create_swarm(local_key: identity::Keypair) -> Result<Swarm<KadBehaviour<MemoryStore>>, DhtError> {
    let builder = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_other_transport(build_transport)
        .map_err(|err| DhtError::transport(err))?
        .with_behaviour(build_kad_behaviour)
        .map_err(|err| DhtError::transport(err))?;

    Ok(builder.build())
}

#[inline(always)]
fn build_transport(
    local_key: &identity::Keypair,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, Box<dyn Error + Send + Sync>> {
    let tcp_config = tcp::Config::default().nodelay(true);
    let base_transport = tcp::tokio::Transport::new(tcp_config);

    let noise_config =
        noise::Config::new(local_key).map_err(|err| -> Box<dyn Error + Send + Sync> { Box::new(err) })?;

    Ok(base_transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise_config)
        .multiplex(yamux::Config::default())
        .boxed())
}

#[inline(always)]
fn build_kad_behaviour(keypair: &identity::Keypair) -> KadBehaviour<MemoryStore> {
    let peer_id = PeerId::from(keypair.public());
    let store = MemoryStore::new(peer_id);
    KadBehaviour::new(peer_id, store)
}

#[inline(always)]
fn decode_beacon_record(bytes: &[u8]) -> Option<BeaconRecord> {
    let record = BeaconRecord::decode(bytes).ok()?;
    record.verify().ok()?;
    Some(record)
}

enum QueryResolution {
    Pending,
    Done(Option<BeaconRecord>),
}

async fn await_query_result(
    swarm: &mut Swarm<KadBehaviour<MemoryStore>>,
    query_id: QueryId,
) -> Result<Option<BeaconRecord>, DhtError> {
    let query_future = async {
        while let Some(event) = swarm.next().await {
            if let SwarmEvent::Behaviour(KadEvent::OutboundQueryProgressed { id, result, .. }) =
                event
            {
                if id != query_id {
                    continue;
                }

                match handle_query_result(result)? {
                    QueryResolution::Pending => continue,
                    QueryResolution::Done(record) => return Ok(record),
                }
            }
        }
        Ok(None)
    };

    match timeout(DHT_QUERY_TIMEOUT, query_future).await {
        Ok(result) => result,
        Err(_) => Err(DhtError::query("DHT query timed out")),
    }
}

fn handle_query_result(
    result: QueryResult,
) -> Result<QueryResolution, DhtError> {
    match result {
        QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))) => {
            if let Some(record) = decode_beacon_record(peer_record.record.value.as_slice()) {
                Ok(QueryResolution::Done(Some(record)))
            } else {
                Ok(QueryResolution::Pending)
            }
        }
        QueryResult::GetRecord(Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. })) => {
            Ok(QueryResolution::Done(None))
        }
        QueryResult::GetRecord(Err(err)) => Err(DhtError::query(err)),
        _ => Ok(QueryResolution::Pending),
    }
}
