use core::ops::{Deref, DerefMut};

use anyhow::{Error, Result};

use polymesh_dart::{
    curve_tree::{
        AsyncCurveTreeBackend, AsyncCurveTreeWithBackend, CurveTreeLookup, CurveTreeParameters,
        CurveTreePath, CurveTreeRoot, Inner, LeafValue, NodeLocation, SelRerandParameters,
    },
    Error as DartError, LeafIndex, NodeLevel, PallasParameters, VestaParameters,
    ACCOUNT_TREE_HEIGHT, ACCOUNT_TREE_L, ASSET_TREE_HEIGHT, ASSET_TREE_L,
};

pub use polymesh_api::types::polymesh_dart::curve_tree::common::NodeLocation as ChainNodeLocation;
pub use polymesh_api::{Api, TransactionResults};

use super::*;

pub type AssetLeaf = LeafValue<PallasParameters>;
pub type AssetInnerNode = Inner<1, PallasParameters, VestaParameters>;
pub type AssetNodeLocation = NodeLocation<ASSET_TREE_L>;

pub type AccountLeaf = LeafValue<PallasParameters>;
pub type AccountInnerNode = Inner<1, PallasParameters, VestaParameters>;
pub type AccountNodeLocation = NodeLocation<ACCOUNT_TREE_L>;

lazy_static::lazy_static! {
    static ref CURVE_TREE_PARAMETERS: CurveTreeParameters = CurveTreeParameters::new(
        polymesh_dart::MAX_CURVE_TREE_GENS,
        polymesh_dart::MAX_CURVE_TREE_GENS,
    ).expect("Failed to create curve tree parameters");
}

/// Convert off-chain `NodeLocation` to on-chain `NodeLocation`.
pub fn node_location_to_chain<const L: usize>(location: NodeLocation<L>) -> ChainNodeLocation {
    match location {
        NodeLocation::Leaf(leaf_index) => ChainNodeLocation::Leaf(leaf_index),
        NodeLocation::Odd { level, index } => ChainNodeLocation::Odd { level, index },
        NodeLocation::Even { level, index } => ChainNodeLocation::Even { level, index },
    }
}

/// Asset Curve Tree Storage backend.
#[derive(Clone)]
pub struct AssetCurveTreeChainStorage {
    api: Api,
}

impl AssetCurveTreeChainStorage {
    fn new(api: &Api) -> Self {
        Self { api: api.clone() }
    }
}

impl AsyncCurveTreeBackend<ASSET_TREE_L, 1, PallasParameters, VestaParameters>
    for AssetCurveTreeChainStorage
{
    type Error = anyhow::Error;

    async fn new(_height: NodeLevel, _gens_length: usize) -> Result<Self, Self::Error> {
        Err(anyhow::anyhow!(
            "AssetCurveTreeChainStorage does not support new()"
        ))
    }

    async fn parameters(&self) -> &SelRerandParameters<PallasParameters, VestaParameters> {
        &CURVE_TREE_PARAMETERS
    }

    async fn height(&self) -> NodeLevel {
        ASSET_TREE_HEIGHT
    }

    async fn set_height(&mut self, _height: NodeLevel) -> Result<(), Error> {
        Err(anyhow::anyhow!(
            "Read-only storage does not support set_height()"
        ))
    }

    async fn allocate_leaf_index(&mut self) -> LeafIndex {
        Default::default()
    }

    async fn get_leaf(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Option<LeafValue<PallasParameters>>, Error> {
        if let Some(leaf) = self
            .api
            .query()
            .dart_asset()
            .asset_leaves(leaf_index)
            .await?
        {
            Ok(Some(to_scale(&leaf)))
        } else {
            Ok(None)
        }
    }

    async fn set_leaf(
        &mut self,
        _leaf_index: LeafIndex,
        _new_leaf_value: LeafValue<PallasParameters>,
    ) -> Result<Option<LeafValue<PallasParameters>>, Error> {
        Err(anyhow::anyhow!(
            "Read-only storage does not support set_leaf()"
        ))
    }

    async fn leaf_count(&self) -> LeafIndex {
        0
    }

    async fn get_inner_node(
        &self,
        location: NodeLocation<ASSET_TREE_L>,
    ) -> Result<Option<Inner<1, PallasParameters, VestaParameters>>, Error> {
        let location = node_location_to_chain(location);
        if let Some(node) = self
            .api
            .query()
            .dart_asset()
            .asset_inner_nodes(location)
            .await?
        {
            Ok(Some(to_scale(&node)))
        } else {
            Ok(None)
        }
    }

    async fn set_inner_node(
        &mut self,
        _location: NodeLocation<ASSET_TREE_L>,
        _new_node: Inner<1, PallasParameters, VestaParameters>,
    ) -> Result<(), Error> {
        Err(anyhow::anyhow!(
            "Read-only storage does not support set_inner_node()"
        ))
    }
}

pub type AssetCurveTreeType = AsyncCurveTreeWithBackend<
    ASSET_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
    AssetCurveTreeChainStorage,
    anyhow::Error,
>;

pub struct AssetCurveTree(AssetCurveTreeType);

impl Deref for AssetCurveTree {
    type Target = AssetCurveTreeType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AssetCurveTree {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AssetCurveTree {
    pub async fn new(api: &Api) -> Result<Self> {
        let backend = AssetCurveTreeChainStorage::new(api);
        Ok(Self(
            AsyncCurveTreeWithBackend::new_with_backend(backend).await?,
        ))
    }
}

/// Account Curve Tree Storage backend.
#[derive(Clone)]
pub struct AccountCurveTreeChainStorage {
    api: Api,
}

impl AccountCurveTreeChainStorage {
    fn new(api: &Api) -> Self {
        Self { api: api.clone() }
    }
}

impl AsyncCurveTreeBackend<ACCOUNT_TREE_L, 1, PallasParameters, VestaParameters>
    for AccountCurveTreeChainStorage
{
    type Error = anyhow::Error;

    async fn new(_height: NodeLevel, _gens_length: usize) -> Result<Self, Self::Error> {
        Err(anyhow::anyhow!(
            "AccountCurveTreeChainStorage does not support new()"
        ))
    }

    async fn parameters(&self) -> &SelRerandParameters<PallasParameters, VestaParameters> {
        &CURVE_TREE_PARAMETERS
    }

    async fn height(&self) -> NodeLevel {
        ACCOUNT_TREE_HEIGHT
    }

    async fn set_height(&mut self, _height: NodeLevel) -> Result<(), Error> {
        Err(anyhow::anyhow!(
            "Read-only storage does not support set_height()"
        ))
    }

    async fn allocate_leaf_index(&mut self) -> LeafIndex {
        Default::default()
    }

    async fn get_leaf(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Option<LeafValue<PallasParameters>>, Error> {
        if let Some(leaf) = self
            .api
            .query()
            .dart_asset()
            .account_leaves(leaf_index)
            .await?
        {
            Ok(Some(to_scale(&leaf)))
        } else {
            Ok(None)
        }
    }

    async fn set_leaf(
        &mut self,
        _leaf_index: LeafIndex,
        _new_leaf_value: LeafValue<PallasParameters>,
    ) -> Result<Option<LeafValue<PallasParameters>>, Error> {
        Err(anyhow::anyhow!(
            "Read-only storage does not support set_leaf()"
        ))
    }

    async fn leaf_count(&self) -> LeafIndex {
        0
    }

    async fn get_inner_node(
        &self,
        location: NodeLocation<ACCOUNT_TREE_L>,
    ) -> Result<Option<Inner<1, PallasParameters, VestaParameters>>, Error> {
        let location = node_location_to_chain(location);
        if let Some(node) = self
            .api
            .query()
            .dart_asset()
            .account_inner_nodes(location)
            .await?
        {
            Ok(Some(to_scale(&node)))
        } else {
            Ok(None)
        }
    }

    async fn set_inner_node(
        &mut self,
        _location: NodeLocation<ACCOUNT_TREE_L>,
        _new_node: Inner<1, PallasParameters, VestaParameters>,
    ) -> Result<(), Error> {
        Err(anyhow::anyhow!(
            "Read-only storage does not support set_inner_node()"
        ))
    }
}

pub type AccountCurveTreeType = AsyncCurveTreeWithBackend<
    ACCOUNT_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
    AccountCurveTreeChainStorage,
    anyhow::Error,
>;

pub struct AccountCurveTree(AccountCurveTreeType);

impl Deref for AccountCurveTree {
    type Target = AccountCurveTreeType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AccountCurveTree {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AccountCurveTree {
    pub async fn new(api: &Api) -> Result<Self> {
        let backend = AccountCurveTreeChainStorage::new(api);
        Ok(Self(
            AsyncCurveTreeWithBackend::new_with_backend(backend).await?,
        ))
    }
}

pub struct AccountPathAndRoot {
    pub account: AccountLeaf,
    pub leaf_index: LeafIndex,
    pub path: CurveTreePath<ACCOUNT_TREE_L>,
    pub root: CurveTreeRoot<ACCOUNT_TREE_L>,
}

impl AccountPathAndRoot {
    pub async fn lookup(
        account_tree: &AccountCurveTree,
        leaf_index: LeafIndex,
        account: AccountLeaf,
    ) -> Result<Self> {
        // Get the leaf and path for the given leaf index.
        let leaf = account_tree
            .get_leaf(leaf_index)
            .await?
            .ok_or_else(|| DartError::LeafIndexNotFound(leaf_index))?;
        // Check if the leaf matches the provided account.
        if leaf != account {
            return Err(DartError::LeafNotFound(account).into());
        }
        let path = account_tree.get_path_to_leaf(leaf_index, 0).await?;
        let root = CurveTreeRoot::new(&account_tree.root_node().await?)?;
        Ok(Self {
            account,
            leaf_index,
            path,
            root,
        })
    }
}

impl CurveTreeLookup<ACCOUNT_TREE_L> for AccountPathAndRoot {
    fn get_path_to_leaf_index(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<CurveTreePath<ACCOUNT_TREE_L>, DartError> {
        if self.leaf_index == leaf_index {
            Ok(self.path.clone())
        } else {
            Err(DartError::LeafIndexNotFound(leaf_index))
        }
    }

    fn get_path_to_leaf(
        &self,
        leaf: LeafValue<PallasParameters>,
    ) -> Result<CurveTreePath<ACCOUNT_TREE_L>, DartError> {
        if self.account == leaf {
            Ok(self.path.clone())
        } else {
            Err(DartError::LeafNotFound(leaf))
        }
    }

    fn params(&self) -> &CurveTreeParameters {
        &CURVE_TREE_PARAMETERS
    }

    fn root_node(&self) -> Result<CurveTreeRoot<ACCOUNT_TREE_L>, DartError> {
        Ok(self.root.clone())
    }
}
