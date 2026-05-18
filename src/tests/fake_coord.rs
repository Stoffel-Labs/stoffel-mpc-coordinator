use ark_bls12_381::Fr;
use stoffelmpc_mpc::common::SecretSharingScheme;
#[cfg(feature = "avss")]
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
#[cfg(feature = "avss")]
use ark_bls12_381::G1Projective;
#[cfg(not(feature = "avss"))]
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

pub type FakeShareValueType = Fr;

#[cfg(not(feature = "avss"))]
pub type FakeShareType = RobustShare<FakeShareValueType>;

#[cfg(feature = "avss")]
pub type FakeShareGroupType = G1Projective;
#[cfg(feature = "avss")]
pub type FakeShareType = FeldmanShamirShare<FakeShareValueType, FakeShareGroupType>;

pub type FakeValueType = <FakeShareType as SecretSharingScheme<FakeShareValueType>>::SecretType;

pub mod on_chain {
    use super::*;
    use crate::on_chain::OnChainCoordinator;

    pub type FakeOnChainCoordinator<P> = OnChainCoordinator<P, FakeShareValueType, FakeShareType>;

    pub type FakeNodeRPCClient = crate::on_chain::node_rpc::NodeRPCClient<FakeShareValueType, FakeShareType>;
    pub type FakeNodeRPCServer<P> = crate::on_chain::node_rpc::NodeRPCServer<P, FakeShareValueType, FakeShareType>;
}

pub mod off_chain {
    use super::*;
    use crate::{Round, off_chain::{ClientIdentity, OffChainCoordinatorClient, OffChainCoordinatorServer, CoordinatorRPCServerSharedBase, CoordinatorRPCServerConnectionBase, StoffelCoordinatorRPCServer, CoordinatorRPCBaseServer}};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use jsonrpsee::{RpcModule, core::RpcResult};
    use async_trait::async_trait;

    pub type FakeOffChainCoordinatorClient = OffChainCoordinatorClient<FakeShareValueType, FakeShareType>;
    pub type FakeOffChainCoordinatorServer = OffChainCoordinatorServer<FakeCoordinatorConnection>;
    pub type FakeCoordinatorRPCServerSharedBase = CoordinatorRPCServerSharedBase<FakeValueType>;

    pub type FakeNodeRPCClient = crate::off_chain::node_rpc::NodeRPCClient<FakeShareValueType, FakeShareType>;
    pub type FakeNodeRPCServer = crate::off_chain::node_rpc::NodeRPCServer<FakeShareValueType, FakeShareType>;

    #[derive(Clone)]
    pub struct FakeCoordinatorConnection {
        base: CoordinatorRPCServerConnectionBase<FakeShareValueType, FakeShareType>,
    }

    impl crate::rpc::RPCServerConnection for FakeCoordinatorConnection {
        type Internal = CoordinatorRPCServerSharedBase<FakeValueType>;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
            Self {
                base: CoordinatorRPCServerConnectionBase::new(internal, id)
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
}
