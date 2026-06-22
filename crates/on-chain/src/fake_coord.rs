use stoffel_mpc_coordinator_shared::tests::fake_coord::{
    AvssShareType, AvssShareValueType, HoneyBadgerShareType, HoneyBadgerShareValueType,
};

use crate::node_rpc::{NodeRPCClient, NodeRPCServer};
use crate::OnChainCoordinator;

pub type HoneyBadgerOnChainCoordinator<P> =
    OnChainCoordinator<P, HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type HoneyBadgerNodeRPCClient = NodeRPCClient<HoneyBadgerShareValueType, HoneyBadgerShareType>;
pub type HoneyBadgerNodeRPCServer<P> =
    NodeRPCServer<P, HoneyBadgerShareValueType, HoneyBadgerShareType>;

pub type AvssOnChainCoordinator<P> = OnChainCoordinator<P, AvssShareValueType, AvssShareType>;
pub type AvssNodeRPCClient = NodeRPCClient<AvssShareValueType, AvssShareType>;
pub type AvssNodeRPCServer<P> = NodeRPCServer<P, AvssShareValueType, AvssShareType>;
