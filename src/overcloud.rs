use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use creep::Context;

use rlp::Decodable;
use rlp::DecoderError;
use rlp::Encodable;
use rlp::Prototype;
use rlp::Rlp;
use rlp::RlpStream;
// use crossbeam_channel::{unbounded, Receiver, Sender};
// use hasher::{Hasher, HasherKeccak};
// use lazy_static::lazy_static;
// use rand::random;
// use serde::{Deserialize, Serialize};

use log::warn;
use tokio::sync::mpsc;

use bls_amcl::common::SigKey;
use bls_amcl::common::VerKey;
use overlord::error::ConsensusError;
use overlord::types::{Address, Commit, Hash, Node, OverlordMsg, Status};

use overlord::{Codec, Consensus, DurationConfig, Overlord, OverlordHandler, Wal};

use crate::crypto::CloudCrypto;
use crate::crypto::VoterInfo;
use crate::error::CloudError;
use crate::mailbox::Mailbox;
use crate::mailbox::MailboxControl;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Wind;

pub struct CloudWal {
    inner: std::sync::Mutex<Option<Bytes>>,
}

impl CloudWal {
    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait]
impl Wal for CloudWal {
    async fn save(&self, info: Bytes) -> Result<(), Box<dyn Error + Send>> {
        *self.inner.lock().unwrap() = Some(info);
        Ok(())
    }

    async fn load(&self) -> Result<Option<Bytes>, Box<dyn Error + Send>> {
        Ok(self.inner.lock().unwrap().as_ref().cloned())
    }
}

#[derive(Debug)]
struct Cloud {
    local_addr: Address,
    peers: Vec<Node>,
    mailbox_control: MailboxControl<CloudMsg>,
    block_interval: u64,
}

impl Cloud {
    fn new(
        local_addr: Address,
        peers: Vec<Node>,
        mailbox_control: MailboxControl<CloudMsg>,
        block_interval: u64,
    ) -> Self {
        Self {
            local_addr,
            peers,
            mailbox_control,
            block_interval,
        }
    }
}

pub struct Overcloud {
    overlord: Overlord<Wind, Cloud, CloudCrypto, CloudWal>,
    peer_nodes: Vec<Node>,
    mailbox_control: MailboxControl<CloudMsg>,
}

pub struct PeerInfo {
    pub id: usize,
    pub addr: Address,
    pub ver_key: VerKey,
}

impl Overcloud {
    pub async fn new(
        local_addr: Address,
        sig_key: SigKey,
        peer_infos: Vec<PeerInfo>,
        controller_port: u16,
        network_port: u16,
        block_interval: u64,
    ) -> Self {
        let (mailbox_sender, mailbox_receiver) = mpsc::unbounded_channel();
        let mut mailbox = Mailbox::new(
            local_addr.clone(),
            controller_port,
            network_port,
            mailbox_sender,
        )
        .await;
        let mailbox_control = mailbox.control();

        let peer_nodes: Vec<Node> = peer_infos
            .iter()
            .map(|info| Node::new(info.addr.clone()))
            .collect();

        let cloud = Arc::new(Cloud::new(
            local_addr.clone(),
            peer_nodes.clone(),
            mailbox_control.clone(),
            block_interval,
        ));

        let voter_infos = peer_infos
            .iter()
            .map(|info| {
                let voter_info = VoterInfo {
                    id: info.id,
                    ver_key: info.ver_key.clone(),
                };
                (info.addr.clone(), voter_info)
            })
            .collect();
        let crypto = Arc::new(CloudCrypto::new(sig_key, voter_infos));
        let wal = Arc::new(CloudWal::new());
        let overlord = Overlord::new(local_addr, cloud, crypto, wal);

        let overlord_handler = overlord.get_handler();
        overlord_handler
            .send_msg(
                Context::new(),
                OverlordMsg::RichStatus(Status {
                    height: 1,
                    interval: Some(block_interval),
                    timer_config: None,
                    authority_list: peer_nodes.clone(),
                }),
            )
            .unwrap();

        tokio::spawn(async move {
            mailbox.run().await;
        });

        tokio::spawn(async move {
            Self::handle_msg(mailbox_receiver, overlord_handler).await;
        });

        Self {
            overlord,
            peer_nodes,
            mailbox_control,
        }
    }

    pub fn control(&self) -> MailboxControl<CloudMsg> {
        self.mailbox_control.clone()
    }

    pub async fn run(
        &self,
        interval: u64,
        timer_config: Option<DurationConfig>,
    ) -> Result<(), Box<dyn Error + Send>> {
        self.overlord
            .run(interval, self.peer_nodes.clone(), timer_config)
            .await
            .unwrap();
        Ok(())
    }

    async fn handle_msg(
        mut mailbox_receiver: mpsc::UnboundedReceiver<CloudMsg>,
        overlord_handler: OverlordHandler<Wind>,
    ) {
        while let Some(CloudMsg { msg, .. }) = mailbox_receiver.recv().await {
            if let Err(e) = overlord_handler.send_msg(Context::new(), msg) {
                warn!("overlord handle report error: `{}`", e);
            }
        }
    }
}

#[async_trait]
impl Consensus<Wind> for Cloud {
    /// Get a block of the given height and return the block with its hash.
    async fn get_block(
        &self,
        _ctx: Context,
        _height: u64,
    ) -> Result<(Wind, Hash), Box<dyn Error + Send>> {
        match self.mailbox_control.get_proposal().await {
            Ok(block_hash) => Ok((Wind, block_hash.into())),
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Check the correctness of a block. If is passed, return the integrated transcations to do
    /// data persistence.
    async fn check_block(
        &self,
        _ctx: Context,
        _height: u64,
        hash: Hash,
        _block: Wind,
    ) -> Result<(), Box<dyn Error + Send>> {
        let hash = Vec::from(hash.as_ref());
        match self.mailbox_control.check_proposal(hash).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(Box::new(CloudError::InvaildBlock)),
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Commit a given height to execute and return the rich status.
    async fn commit(
        &self,
        ctx: Context,
        height: u64,
        commit: Commit<Wind>,
    ) -> Result<Status, Box<dyn Error + Send>> {
        let block_hash = Vec::from(commit.proof.block_hash.as_ref());
        self.mailbox_control.commit_block(block_hash).await?;
        Ok(Status {
            height: height + 1,
            interval: None,
            timer_config: None,
            authority_list: self.get_authority_list(ctx, height).await?,
        })
    }

    /// Get an authority list of the given height.
    async fn get_authority_list(
        &self,
        _ctx: Context,
        _height: u64,
    ) -> Result<Vec<Node>, Box<dyn Error + Send>> {
        Ok(self.peers.clone())
    }

    /// Broadcast a message to other replicas.
    async fn broadcast_to_other(
        &self,
        _ctx: Context,
        msg: OverlordMsg<Wind>,
    ) -> Result<(), Box<dyn Error + Send>> {
        let msg = CloudMsg {
            from: self.local_addr.clone(),
            to: None,
            msg,
        };
        self.mailbox_control
            .broadcast_message(msg)
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
    }

    /// Transmit a message to the Relayer, the third argument is the relayer's address.
    async fn transmit_to_relayer(
        &self,
        _ctx: Context,
        addr: Address,
        msg: OverlordMsg<Wind>,
    ) -> Result<(), Box<dyn Error + Send>> {
        let msg = CloudMsg {
            from: self.local_addr.clone(),
            to: Some(addr),
            msg,
        };
        self.mailbox_control
            .send_message(msg)
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
    }

    /// Report the overlord error with the corresponding context.
    fn report_error(&self, _ctx: Context, error: ConsensusError) {
        warn!("report error: `{}`", error);
    }
}

impl Codec for Wind {
    fn encode(&self) -> Result<Bytes, Box<dyn Error + Send>> {
        Ok(Bytes::new())
    }

    fn decode(_data: Bytes) -> Result<Self, Box<dyn Error + Send>> {
        Ok(Self)
    }
}

#[derive(Clone, Debug)]
pub struct CloudMsg {
    from: Address,
    to: Option<Address>,
    msg: OverlordMsg<Wind>,
}

impl Encodable for CloudMsg {
    fn rlp_append(&self, s: &mut RlpStream) {
        let s = s.begin_list(4);
        let from = self.from.iter().copied().collect::<Vec<u8>>();
        let to = match &self.to {
            Some(addr) => Some(addr.iter().copied().collect::<Vec<u8>>()),
            None => None,
        };
        s.append(&from);
        s.append(&to);
        match &self.msg {
            OverlordMsg::SignedProposal(sp) => {
                s.append(&0u8);
                s.append(sp);
            }
            OverlordMsg::SignedVote(sv) => {
                s.append(&1u8);
                s.append(sv);
            }
            OverlordMsg::AggregatedVote(av) => {
                s.append(&2u8);
                s.append(av);
            }
            OverlordMsg::RichStatus(rs) => {
                s.append(&3u8);
                s.append(rs);
            }
            OverlordMsg::SignedChoke(sc) => {
                s.append(&4u8);
                s.append(sc);
            }
            OverlordMsg::Stop => {
                s.append(&5u8);
            }
            #[cfg(test)]
            OverlordMsg::Commit(c) => {
                s.append(&6u8);
                s.append(c);
            }
        }
    }
}

impl Decodable for CloudMsg {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.prototype()? {
            Prototype::List(4) => {
                let from = rlp.val_at::<Vec<u8>>(0)?;
                let from = Bytes::from(from);
                let to = rlp.val_at::<Option<Vec<u8>>>(1)?;
                let to = to.map(Bytes::from);
                let msg_type: u8 = rlp.val_at(2)?;
                let msg = match msg_type {
                    0 => {
                        let sp = rlp.val_at(3)?;
                        OverlordMsg::SignedProposal(sp)
                    }
                    1 => {
                        let sv = rlp.val_at(3)?;
                        OverlordMsg::SignedVote(sv)
                    }
                    2 => {
                        let av = rlp.val_at(3)?;
                        OverlordMsg::AggregatedVote(av)
                    }
                    3 => {
                        let rs = rlp.val_at(3)?;
                        OverlordMsg::RichStatus(rs)
                    }
                    4 => {
                        let sc = rlp.val_at(3)?;
                        OverlordMsg::SignedChoke(sc)
                    }
                    5 => OverlordMsg::Stop,
                    #[cfg(test)]
                    6 => {
                        let c = rlp.val_at(3)?;
                        OverlordMsg::Commit(c)
                    }
                    _ => return Err(DecoderError::Custom("Invaild data")),
                };
                Ok(CloudMsg { from, to, msg })
            }
            _ => Err(DecoderError::RlpInconsistentLengthAndData),
        }
    }
}

impl crate::mailbox::Letter for CloudMsg {
    type Address = Address;
    type ReadError = Box<dyn Error + Send>;
    fn from(&self) -> Address {
        self.from.clone()
    }
    fn to(&self) -> Option<Self::Address> {
        self.to.clone()
    }
    fn write_down(&self) -> Vec<u8> {
        rlp::encode(self)
    }
    fn read_from(paper: &[u8]) -> Result<Self, Self::ReadError> {
        rlp::decode(paper).map_err(|e| Box::new(e) as Box<dyn Error + Send>)
    }
}
