use log::info;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time;
use tonic::transport::channel::Channel;

use cita_cloud_proto::common::{Empty, Hash};
use cita_cloud_proto::controller::consensus2_controller_service_client::Consensus2ControllerServiceClient;

use cita_cloud_proto::network::{network_service_client::NetworkServiceClient, NetworkMsg};

use std::fmt::Debug;

// use anyhow::Result;
use crate::error::Result;

type ControllerClient = Consensus2ControllerServiceClient<Channel>;
type NetworkClient = NetworkServiceClient<Channel>;

pub trait Letter: Clone + Debug + Send + Sized + 'static {
    type Address: std::hash::Hash + std::cmp::Eq;
    type ReadError: Debug;
    fn to(&self) -> Option<Self::Address>;
    fn from(&self) -> Self::Address;
    fn write_down(&self) -> Vec<u8>;
    fn read_from(paper: &[u8]) -> std::result::Result<Self, Self::ReadError>;
}

pub struct Mailbox<T: Letter> {
    local_addr: T::Address,
    mail_put: mpsc::UnboundedSender<Mail<T>>,
    mail_get: mpsc::UnboundedReceiver<Mail<T>>,
    mailbook: HashMap<T::Address, u64>,
    controller_sender: mpsc::UnboundedSender<ControllerMail>,
    network_sender: mpsc::UnboundedSender<NetworkMail<T>>,
    send_to: mpsc::UnboundedSender<T>,
}

#[derive(Debug)]
pub enum Mail<T: Letter> {
    ToMe { origin: u64, mail: MyMail<T> },
    ToController(ControllerMail),
    ToNetwork(NetworkMail<T>),
}

#[derive(Debug)]
pub enum MyMail<T: Letter> {
    Normal {
        msg: T,
        reply_tx: oneshot::Sender<Result<()>>,
    },
}

#[derive(Debug)]
pub enum ControllerMail {
    GetProposal {
        reply_tx: oneshot::Sender<Result<Vec<u8>>>,
    },
    CheckProposal {
        proposal: Vec<u8>,
        reply_tx: oneshot::Sender<Result<bool>>,
    },
    CommitBlock {
        block_hash: Vec<u8>,
        reply_tx: oneshot::Sender<Result<()>>,
    },
}

#[derive(Debug)]
pub enum NetworkMail<T: Letter> {
    SendMessage {
        session_id: Option<u64>,
        msg: T,
        reply_tx: oneshot::Sender<Result<()>>,
    },
    BroadcastMessage {
        msg: T,
        reply_tx: oneshot::Sender<Result<()>>,
    },
}

#[derive(Clone, Debug)]
pub struct MailboxControl<T: Letter> {
    mail_put: mpsc::UnboundedSender<Mail<T>>,
}

impl<T: Letter> MailboxControl<T> {
    pub async fn put_mail(&self, origin: u64, msg: T) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mail = MyMail::Normal { msg, reply_tx };
        self.mail_put
            .clone()
            .send(Mail::ToMe { origin, mail })
            .unwrap();
        reply_rx.await.unwrap()
    }

    pub async fn get_proposal(&self) -> Result<Vec<u8>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mail = ControllerMail::GetProposal { reply_tx };
        self.mail_put
            .clone()
            .send(Mail::ToController(mail))
            .unwrap();
        reply_rx.await.unwrap()
    }

    pub async fn check_proposal(&self, proposal: Vec<u8>) -> Result<bool> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mail = ControllerMail::CheckProposal { proposal, reply_tx };
        self.mail_put
            .clone()
            .send(Mail::ToController(mail))
            .unwrap();
        reply_rx.await.unwrap()
    }

    pub async fn commit_block(&self, block_hash: Vec<u8>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mail = ControllerMail::CommitBlock {
            block_hash,
            reply_tx,
        };
        self.mail_put
            .clone()
            .send(Mail::ToController(mail))
            .unwrap();
        reply_rx.await.unwrap()
    }

    pub async fn send_message(&self, msg: T) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mail = NetworkMail::SendMessage {
            session_id: None,
            msg,
            reply_tx,
        };
        self.mail_put.clone().send(Mail::ToNetwork(mail)).unwrap();
        reply_rx.await.unwrap()
    }

    pub async fn broadcast_message(&self, msg: T) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mail = NetworkMail::BroadcastMessage { msg, reply_tx };
        self.mail_put.clone().send(Mail::ToNetwork(mail)).unwrap();
        reply_rx.await.unwrap()
    }
}

impl<T: Letter> Mailbox<T> {
    pub async fn new(
        local_addr: T::Address,
        controller_port: u16,
        network_port: u16,
        send_to: mpsc::UnboundedSender<T>,
    ) -> Self {
        let (controller_sender, controller_receiver) = mpsc::unbounded_channel();
        let (network_sender, network_receiver) = mpsc::unbounded_channel();
        let controller_client = Self::connect_controller(controller_port).await;
        let network_client = Self::connect_network(network_port).await;
        tokio::spawn(Self::serve_controller(
            controller_client,
            controller_receiver,
        ));
        tokio::spawn(Self::serve_network(network_client, network_receiver));
        let (mail_put, mail_get) = mpsc::unbounded_channel();
        let _control = MailboxControl {
            mail_put: mail_put.clone(),
        };
        Self {
            local_addr,
            mailbook: HashMap::new(),
            mail_put,
            mail_get,
            controller_sender,
            network_sender,
            send_to,
        }
    }

    pub async fn run(&mut self) {
        while let Some(m) = self.mail_get.recv().await {
            self.handle_mail(m);
        }
    }

    fn handle_mail(&mut self, mail: Mail<T>) {
        use Mail::*;
        match mail {
            ToMe { origin, mail } => match mail {
                MyMail::Normal { msg, reply_tx } => {
                    let from = msg.from();
                    let to = msg.to();
                    if to.is_none() || to.as_ref() == Some(&self.local_addr) {
                        self.mailbook.insert(from, origin);
                        self.send_to.send(msg).unwrap();
                    }
                    reply_tx.send(Ok(())).unwrap();
                }
            },
            ToController(m) => {
                self.controller_sender.send(m).unwrap();
            }
            ToNetwork(mut m) => {
                if let NetworkMail::SendMessage {
                    session_id, msg, ..
                } = &mut m
                {
                    let to = msg.to();
                    assert!(to.is_some(), "Mail dest must exist. To broadcast, use NetworkMail::BroadcastMessage instead.");
                    let to = to.unwrap();
                    if let Some(origin) = self.mailbook.get(&to).copied() {
                        *session_id = Some(origin);
                    }
                }
                self.network_sender.send(m).unwrap();
            }
        }
    }

    pub fn control(&self) -> MailboxControl<T> {
        MailboxControl {
            mail_put: self.mail_put.clone(),
        }
    }

    async fn serve_controller(
        mut controller: ControllerClient,
        mut controller_receiver: mpsc::UnboundedReceiver<ControllerMail>,
    ) {
        while let Some(mail) = controller_receiver.recv().await {
            use ControllerMail::*;
            match mail {
                GetProposal { reply_tx } => {
                    let request = tonic::Request::new(Empty {});
                    let response = controller
                        .get_proposal(request)
                        .await
                        .map(|resp| resp.into_inner().hash)
                        .map_err(|e| e.into());
                    let _ = reply_tx.send(response);
                }
                CheckProposal { proposal, reply_tx } => {
                    let request = tonic::Request::new(Hash { hash: proposal });
                    let response = controller
                        .check_proposal(request)
                        .await
                        .map(|resp| resp.into_inner().is_success)
                        .map_err(|e| e.into());
                    let _ = reply_tx.send(response);
                }
                CommitBlock {
                    block_hash,
                    reply_tx,
                } => {
                    let request = tonic::Request::new(Hash { hash: block_hash });
                    let response = controller
                        .commit_block(request)
                        .await
                        .map(|_resp| ())
                        .map_err(|e| e.into());
                    let _ = reply_tx.send(response);
                }
            }
        }
    }

    async fn serve_network(
        mut network: NetworkClient,
        mut network_receiver: mpsc::UnboundedReceiver<NetworkMail<T>>,
    ) {
        while let Some(mail) = network_receiver.recv().await {
            use NetworkMail::*;
            match mail {
                SendMessage {
                    session_id: Some(origin),
                    msg,
                    reply_tx,
                } => {
                    let request = tonic::Request::new(NetworkMsg {
                        module: "consensus".to_owned(),
                        r#type: "overcloud".to_owned(),
                        origin,
                        msg: msg.write_down(),
                    });
                    let resp = network
                        .send_msg(request)
                        .await
                        .map(|_resp| ())
                        .map_err(|e| e.into());
                    let _ = reply_tx.send(resp);
                }
                SendMessage {
                    session_id: None,
                    msg,
                    reply_tx,
                }
                | BroadcastMessage { msg, reply_tx } => {
                    let request = tonic::Request::new(NetworkMsg {
                        module: "consensus".to_owned(),
                        r#type: "overcloud".to_owned(),
                        origin: 0,
                        msg: msg.write_down(),
                    });
                    let resp = network
                        .broadcast(request)
                        .await
                        .map(|_resp| ())
                        .map_err(|e| e.into());
                    let _ = reply_tx.send(resp);
                }
            }
        }
    }

    async fn connect_controller(controller_port: u16) -> ControllerClient {
        let d = Duration::from_secs(1);
        let mut interval = time::interval(d);
        let controller_addr = format!("http://127.0.0.1:{}", controller_port);
        info!("connecting to controller...");
        loop {
            interval.tick().await;
            match Consensus2ControllerServiceClient::connect(controller_addr.clone()).await {
                Ok(client) => return client,
                Err(e) => {
                    info!("connect to controller failed: `{}`", e);
                }
            }
            info!("Retrying to connect controller");
        }
    }

    async fn connect_network(network_port: u16) -> NetworkClient {
        let d = Duration::from_secs(1);
        let mut interval = time::interval(d);
        let network_addr = format!("http://127.0.0.1:{}", network_port);
        info!("connecting to network...");
        loop {
            interval.tick().await;
            match NetworkServiceClient::connect(network_addr.clone()).await {
                Ok(client) => return client,
                Err(e) => {
                    info!("connect to network failed: `{}`", e);
                }
            }
            info!("Retrying to connect network");
        }
    }
}

use cita_cloud_proto::common::SimpleResponse;
use cita_cloud_proto::consensus::{
    consensus_service_server::ConsensusService, ConsensusConfiguration,
};
use cita_cloud_proto::network::network_msg_handler_service_server::NetworkMsgHandlerService;

#[derive(Clone)]
pub struct Poste<T: Letter> {
    pub mailbox_control: MailboxControl<T>,
}

#[tonic::async_trait]
impl<T: Letter> NetworkMsgHandlerService for Poste<T> {
    async fn process_network_msg(
        &self,
        request: tonic::Request<NetworkMsg>,
    ) -> std::result::Result<tonic::Response<SimpleResponse>, tonic::Status> {
        info!("process_network_msg request: {:?}", request);

        let msg = request.into_inner();
        if msg.module != "consensus" {
            Err(tonic::Status::invalid_argument("wrong module"))
        } else {
            let letter = Letter::read_from(msg.msg.as_slice()).map_err(|e| {
                tonic::Status::invalid_argument(format!("msg fail to decode: `{:?}`", e))
            })?;
            let origin = msg.origin;
            self.mailbox_control.put_mail(origin, letter).await.unwrap();
            let reply = SimpleResponse { is_success: true };
            Ok(tonic::Response::new(reply))
        }
    }
}

#[tonic::async_trait]
impl<T: Letter> ConsensusService for Poste<T> {
    async fn reconfigure(
        &self,
        request: tonic::Request<ConsensusConfiguration>,
    ) -> std::result::Result<tonic::Response<SimpleResponse>, tonic::Status> {
        info!("reconfigure request: {:?}", request);
        // TODO
        let reply = SimpleResponse { is_success: true };
        Ok(tonic::Response::new(reply))
    }
}
