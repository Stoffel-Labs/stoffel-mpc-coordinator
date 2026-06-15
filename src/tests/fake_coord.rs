use ark_ff::FftField;
use ark_bls12_381::Fr;
use ark_bls12_381::G1Projective;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
#[cfg(feature = "on-chain")]
use crate::on_chain::node_rpc::NodeRPCClient;
#[cfg(feature = "on-chain")]
use crate::on_chain::node_rpc::NodeRPCServer;

pub type HoneyBadgerShareValueType = Fr;
pub type HoneyBadgerValueType = Fr;
pub type HoneyBadgerShareType = RobustShare<HoneyBadgerShareValueType>;

pub type AvssShareGroupType = G1Projective;
pub type AvssShareValueType = Fr;
pub type AvssValueType = Fr;
pub type AvssShareType = FeldmanShamirShare<AvssShareValueType, AvssShareGroupType>;

#[cfg(feature = "on-chain")]
pub mod on_chain {
    use super::*;
    use crate::on_chain::OnChainCoordinator;

    pub type HoneyBadgerOnChainCoordinator<P> = OnChainCoordinator<P, HoneyBadgerShareValueType, HoneyBadgerShareType>;
    pub type HoneyBadgerNodeRPCClient = NodeRPCClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
    pub type HoneyBadgerNodeRPCServer<P> = NodeRPCServer<P, HoneyBadgerShareValueType, HoneyBadgerShareType>;

    pub type AvssOnChainCoordinator<P> = OnChainCoordinator<P, AvssShareValueType, AvssShareType>;
    pub type AvssNodeRPCClient = NodeRPCClient<AvssShareValueType, AvssShareType>;
    pub type AvssNodeRPCServer<P> = NodeRPCServer<P, AvssShareValueType, AvssShareType>;
}

#[cfg(feature = "off-chain")]
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
        OffChainCoordinatorClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
    pub type AvssOffChainCoordinatorClient =
        OffChainCoordinatorClient<HoneyBadgerShareValueType, AvssShareType>;

    pub type HoneyBadgerOffChainCoordinatorServer =
        OffChainCoordinatorServer<HoneyBadgerCoordinatorConnection>;
    pub type HoneyBadgerCoordinatorRPCServerSharedBase = CoordinatorRPCServerSharedBase<HoneyBadgerValueType>;
    pub type AvssOffChainCoordinatorServer = OffChainCoordinatorServer<AvssCoordinatorConnection>;
    pub type AvssCoordinatorRPCServerSharedBase = CoordinatorRPCServerSharedBase<AvssValueType>;

    pub type HoneyBadgerNodeRPCClient =
        crate::off_chain::node_rpc::NodeRPCClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
    pub type AvssNodeRPCClient =
        crate::off_chain::node_rpc::NodeRPCClient<AvssShareValueType, AvssShareType>;

    pub type HoneyBadgerNodeRPCServer =
        crate::off_chain::node_rpc::NodeRPCServer<HoneyBadgerShareValueType, HoneyBadgerShareType>;
    pub type AvssNodeRPCServer =
        crate::off_chain::node_rpc::NodeRPCServer<AvssShareValueType, AvssShareType>;

    /// Below is shown how to define your own off-chain coordinator. `CoordinatorRPCServerConnectionBase` is the data
    /// that is stored on the coordinator and shared among connections to all coordinator clients, i.e., MPC clients
    /// or MPC nodes. For a new off-chain coordinator, a struct for a connection like `CoordinatorConnection` needs to
    /// be defined. This should probably contain a `CoordinatorRPCServerConnectionBase` object, but
    /// can also contain other per-connection data.
    /// The connection struct then needs to implement the `RPCServerConnection` and `StoffelCoordinatorRPCServer` traits.
    ///
    /// A connection struct for the fake coordinators.
    #[derive(Clone)]
    pub struct CoordinatorConnection<F: FftField, S: crate::ShareBound<F>> {
        base: CoordinatorRPCServerConnectionBase<F, S>,
    }

    /// The two trait implementations below are for the fake coordinator. Since there are two
    /// variants for HB and AVSS, which both have the same types for share values and secret
    /// values, we have one implementation per trait and instantiate them for HB and AVSS.
    pub type HoneyBadgerCoordinatorConnection = CoordinatorConnection<HoneyBadgerShareValueType, HoneyBadgerShareType>;
    pub type AvssCoordinatorConnection = CoordinatorConnection<AvssShareValueType, AvssShareType>;


    impl<S: crate::ShareBound<Fr, ValueType = Fr>>
        crate::rpc::RPCServerConnection for CoordinatorConnection<Fr, S>
    {
        type Internal = CoordinatorRPCServerSharedBase<Fr>;

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
    impl<S: crate::ShareBound<Fr, ValueType = Fr>>
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
}
