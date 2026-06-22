use stoffel_mpc_coordinator_shared::tests::fake_coord::{
    AvssShareType, AvssShareValueType, AvssValueType,
    HoneyBadgerShareType, HoneyBadgerShareValueType, HoneyBadgerValueType,
};
use crate::{
    CoordinatorRPCBaseServer, CoordinatorRPCServerConnectionBase, CoordinatorRPCServerSharedBase,
    OffChainCoordinatorClient, OffChainCoordinatorServer, StoffelCoordinatorRPCServer,
};
use ark_bls12_381::Fr;
use ark_ff::FftField;
use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, RpcModule};
use std::sync::Arc;
use tokio::sync::Mutex;
use stoffel_mpc_coordinator_shared::Round;

pub type HoneyBadgerOffChainCoordinatorClient =
    OffChainCoordinatorClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type AvssOffChainCoordinatorClient =
    OffChainCoordinatorClient<HoneyBadgerShareValueType, AvssShareType>;

pub type HoneyBadgerOffChainCoordinatorServer =
    OffChainCoordinatorServer<HoneyBadgerCoordinatorConnection>;
pub type HoneyBadgerCoordinatorRPCServerSharedBase =
    CoordinatorRPCServerSharedBase<HoneyBadgerValueType>;
pub type AvssOffChainCoordinatorServer = OffChainCoordinatorServer<AvssCoordinatorConnection>;
pub type AvssCoordinatorRPCServerSharedBase = CoordinatorRPCServerSharedBase<AvssValueType>;

pub type HoneyBadgerNodeRPCClient =
    crate::node_rpc::NodeRPCClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type AvssNodeRPCClient =
    crate::node_rpc::NodeRPCClient<AvssShareValueType, AvssShareType>;

pub type HoneyBadgerNodeRPCServer =
    crate::node_rpc::NodeRPCServer<HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type AvssNodeRPCServer =
    crate::node_rpc::NodeRPCServer<AvssShareValueType, AvssShareType>;

#[derive(Clone)]
pub struct CoordinatorConnection<F: FftField, S: stoffel_mpc_coordinator_shared::ShareBound<F>> {
    base: CoordinatorRPCServerConnectionBase<F, S>,
}

pub type HoneyBadgerCoordinatorConnection =
    CoordinatorConnection<HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type AvssCoordinatorConnection =
    CoordinatorConnection<AvssShareValueType, AvssShareType>;

impl<S: stoffel_mpc_coordinator_shared::ShareBound<Fr, ValueType = Fr>>
    stoffel_mpc_coordinator_shared::rpc::RPCServerConnection for CoordinatorConnection<Fr, S>
{
    type Internal = CoordinatorRPCServerSharedBase<Fr>;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
        Self {
            base: CoordinatorRPCServerConnectionBase::new(internal, id),
        }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        let mut rpc = crate::StoffelCoordinatorRPCServer::into_rpc(self.clone());
        let base_rpc = crate::CoordinatorRPCBaseServer::into_rpc(self.base);
        rpc.merge(base_rpc).unwrap();
        rpc
    }
}

#[async_trait]
impl<S: stoffel_mpc_coordinator_shared::ShareBound<Fr, ValueType = Fr>>
    StoffelCoordinatorRPCServer for CoordinatorConnection<Fr, S>
{
    async fn start_preprocessing(&self) -> RpcResult<()> {
        self.base.transition(Round::Preprocessing).await
    }

    async fn reserve_input_masks(&self) -> RpcResult<()> {
        self.base.transition(Round::InputMaskReservation).await
    }

    async fn collect_inputs(&self) -> RpcResult<()> {
        self.base.transition(Round::InputCollection).await
    }

    async fn start_mpc(&self) -> RpcResult<()> {
        self.base.transition(Round::MPCExecution).await
    }

    async fn send_output(&self) -> RpcResult<()> {
        self.base.transition(Round::OutputDistribution).await
    }

    async fn finalize(&self) -> RpcResult<()> {
        self.base.transition(Round::ProgramFinished).await
    }
}
