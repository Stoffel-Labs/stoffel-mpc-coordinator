use crate::{
    CoordinatorRPCServerSharedBase, OffChainCoordinatorClient, OffChainCoordinatorConnection,
    OffChainCoordinatorServer,
};
use stoffel_mpc_coordinator_shared::tests::fake_coord::{
    AvssShareType, AvssShareValueType, HoneyBadgerShareType, HoneyBadgerShareValueType,
};

pub type HoneyBadgerOffChainCoordinatorClient =
    OffChainCoordinatorClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type AvssOffChainCoordinatorClient =
    OffChainCoordinatorClient<HoneyBadgerShareValueType, AvssShareType>;

pub type HoneyBadgerOffChainCoordinatorServer =
    OffChainCoordinatorServer<HoneyBadgerCoordinatorConnection>;
pub type HoneyBadgerCoordinatorRPCServerSharedBase = CoordinatorRPCServerSharedBase;
pub type AvssOffChainCoordinatorServer = OffChainCoordinatorServer<AvssCoordinatorConnection>;
pub type AvssCoordinatorRPCServerSharedBase = CoordinatorRPCServerSharedBase;

pub type HoneyBadgerNodeRPCClient =
    crate::node_rpc::NodeRPCClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type AvssNodeRPCClient = crate::node_rpc::NodeRPCClient<AvssShareValueType, AvssShareType>;

pub type HoneyBadgerNodeRPCServer = crate::node_rpc::NodeRPCServer;
pub type AvssNodeRPCServer = crate::node_rpc::NodeRPCServer;

/// The connection type embedders serve, promoted to `OffChainCoordinatorConnection`; kept
/// under its test name so existing embedders keep compiling.
pub type CoordinatorConnection = OffChainCoordinatorConnection;

pub type HoneyBadgerCoordinatorConnection = CoordinatorConnection;
pub type AvssCoordinatorConnection = CoordinatorConnection;
