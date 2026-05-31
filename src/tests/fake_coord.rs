use ark_bls12_381::Fr;
use ark_bls12_381::G1Projective;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

pub type FakeShareValueType = Fr;

pub type HoneyBadgerShareType = RobustShare<FakeShareValueType>;
pub type AvssShareGroupType = G1Projective;
pub type AvssShareType = FeldmanShamirShare<FakeShareValueType, AvssShareGroupType>;

pub type FakeShareType = HoneyBadgerShareType;
pub type FakeValueType = FakeShareValueType;

pub mod on_chain {
    use super::*;
    use crate::on_chain::OnChainCoordinator;

    pub type FakeOnChainCoordinator<P> = OnChainCoordinator<P, FakeShareValueType, FakeShareType>;

    pub type FakeNodeRPCClient =
        crate::on_chain::node_rpc::NodeRPCClient<FakeShareValueType, FakeShareType>;
    pub type FakeNodeRPCServer<P> =
        crate::on_chain::node_rpc::NodeRPCServer<P, FakeShareValueType, FakeShareType>;
}

pub mod off_chain {
    use super::*;
    use crate::{
        off_chain::{
            ClientIdentity, CoordinatorRPCBaseServer, CoordinatorRPCServerConnectionBase,
            CoordinatorRPCServerSharedBase, OffChainCoordinatorClient, OffChainCoordinatorServer,
            StoffelCoordinatorRPCServer,
        },
        Round,
    };
    use async_trait::async_trait;
    use jsonrpsee::{core::RpcResult, RpcModule};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    pub type HoneyBadgerOffChainCoordinatorClient =
        OffChainCoordinatorClient<FakeShareValueType, HoneyBadgerShareType>;
    pub type AvssOffChainCoordinatorClient =
        OffChainCoordinatorClient<FakeShareValueType, AvssShareType>;
    pub type FakeOffChainCoordinatorClient = HoneyBadgerOffChainCoordinatorClient;

    pub type HoneyBadgerOffChainCoordinatorServer =
        OffChainCoordinatorServer<FakeCoordinatorConnection>;
    pub type AvssOffChainCoordinatorServer = OffChainCoordinatorServer<AvssCoordinatorConnection>;
    pub type FakeOffChainCoordinatorServer = OffChainCoordinatorServer<FakeCoordinatorConnection>;
    pub type FakeCoordinatorRPCServerSharedBase = CoordinatorRPCServerSharedBase<FakeValueType>;

    pub type HoneyBadgerNodeRPCClient =
        crate::off_chain::node_rpc::NodeRPCClient<FakeShareValueType, HoneyBadgerShareType>;
    pub type AvssNodeRPCClient =
        crate::off_chain::node_rpc::NodeRPCClient<FakeShareValueType, AvssShareType>;
    pub type FakeNodeRPCClient = HoneyBadgerNodeRPCClient;

    pub type HoneyBadgerNodeRPCServer =
        crate::off_chain::node_rpc::NodeRPCServer<FakeShareValueType, HoneyBadgerShareType>;
    pub type AvssNodeRPCServer =
        crate::off_chain::node_rpc::NodeRPCServer<FakeShareValueType, AvssShareType>;
    pub type FakeNodeRPCServer = HoneyBadgerNodeRPCServer;

    #[derive(Clone)]
    pub struct FakeCoordinatorConnection {
        base: CoordinatorRPCServerConnectionBase<FakeShareValueType, FakeShareType>,
    }

    impl crate::rpc::RPCServerConnection for FakeCoordinatorConnection {
        type Internal = CoordinatorRPCServerSharedBase<FakeValueType>;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
            Self {
                base: CoordinatorRPCServerConnectionBase::new(internal, id),
            }
        }

        fn into_rpc(self) -> RpcModule<Self> {
            let mut rpc = StoffelCoordinatorRPCServer::into_rpc(self.clone());
            let base_rpc = crate::off_chain::CoordinatorRPCBaseServer::into_rpc(self.base);

            rpc.merge(base_rpc).unwrap();
            rpc
        }
    }

    #[async_trait]
    impl StoffelCoordinatorRPCServer for FakeCoordinatorConnection {
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

    #[derive(Clone)]
    pub struct AvssCoordinatorConnection {
        base: CoordinatorRPCServerConnectionBase<FakeShareValueType, AvssShareType>,
    }

    impl crate::rpc::RPCServerConnection for AvssCoordinatorConnection {
        type Internal = CoordinatorRPCServerSharedBase<FakeValueType>;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
            Self {
                base: CoordinatorRPCServerConnectionBase::new(internal, id),
            }
        }

        fn into_rpc(self) -> RpcModule<Self> {
            let mut rpc = StoffelCoordinatorRPCServer::into_rpc(self.clone());
            let base_rpc = crate::off_chain::CoordinatorRPCBaseServer::into_rpc(self.base);

            rpc.merge(base_rpc).unwrap();
            rpc
        }
    }

    #[async_trait]
    impl StoffelCoordinatorRPCServer for AvssCoordinatorConnection {
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
}
