use core::ops::{Deref, DerefMut};
use std::collections::BTreeSet;

use anyhow::{Error, Result};

use polymesh_dart::{
    curve_tree::{
        AsyncCurveTreeBackend, AsyncCurveTreeWithBackend, CurveTreeLookup, CurveTreeParameters,
        CurveTreePath, CurveTreeRoot, Inner, LeafValue, NodeLocation, Root, SelRerandParameters,
    },
    BlockNumber, Error as DartError, LeafIndex, NodeLevel, PallasParameters, VestaParameters,
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
    type BlockNumber = BlockNumber;

    async fn new(_height: NodeLevel, _gens_length: usize) -> Result<Self, Self::Error> {
        Err(anyhow::anyhow!(
            "AssetCurveTreeChainStorage does not support new()"
        ))
    }

    async fn parameters(&self) -> &SelRerandParameters<PallasParameters, VestaParameters> {
        &CURVE_TREE_PARAMETERS
    }

    async fn get_block_number(&self) -> Result<BlockNumber, Self::Error> {
        let last_block_number = self
            .api
            .query()
            .dart_asset()
            .asset_curve_tree_last_update()
            .await?;
        Ok(last_block_number)
    }

    async fn fetch_root(
        &self,
        block_number: Self::BlockNumber,
    ) -> Result<Root<ASSET_TREE_L, 1, PallasParameters, VestaParameters>> {
        let root = self
            .api
            .query()
            .dart_asset()
            .asset_curve_tree_roots(block_number)
            .await?;
        if let Some(root) = root {
            let root: CurveTreeRoot<ASSET_TREE_L> = to_scale(&root);
            Ok(root.decode()?)
        } else {
            Err(anyhow::anyhow!(
                "Root not found for block number {}",
                block_number
            ))
        }
    }

    async fn height(&self) -> NodeLevel {
        ASSET_TREE_HEIGHT
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
}

pub type AssetCurveTreeType = AsyncCurveTreeWithBackend<
    ASSET_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
    AssetCurveTreeChainStorage,
    anyhow::Error,
>;

#[derive(Clone)]
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

/// A syncronous holder for multiple asset leaf paths.
///
/// This is used for creating multi-leg settlements that have different assets.
pub struct AssetLeafPaths {
    pub track_assets: BTreeSet<DartAssetId>,
    pub leaf_index: BTreeMap<Vec<u8>, LeafIndex>,
    pub paths: BTreeMap<LeafIndex, CurveTreePath<ASSET_TREE_L>>,
    pub block_number: BlockNumber,
    pub root: CurveTreeRoot<ASSET_TREE_L>,
}

impl AssetLeafPaths {
    pub async fn new(asset_tree: &AssetCurveTreeType) -> Result<Self> {
        let block_number = asset_tree.get_block_number().await?;
        let root = CurveTreeRoot::new(&asset_tree.fetch_root(block_number).await?)?;
        Ok(Self {
            track_assets: BTreeSet::new(),
            leaf_index: BTreeMap::new(),
            paths: BTreeMap::new(),
            block_number,
            root,
        })
    }

    async fn update_asset_path(
        &mut self,
        asset_id: DartAssetId,
        asset_tree: &AssetCurveTreeType,
    ) -> Result<()> {
        let leaf_index = asset_id as _;
        let leaf = asset_tree
            .get_leaf(leaf_index)
            .await?
            .ok_or_else(|| DartError::LeafIndexNotFound(leaf_index))?;
        let path = asset_tree.get_path_to_leaf(leaf_index, 0).await?;
        self.leaf_index.insert(leaf.encode(), leaf_index);
        self.paths.insert(leaf_index, path);
        Ok(())
    }

    pub async fn update_root(&mut self, asset_tree: &AssetCurveTreeType) -> Result<()> {
        self.block_number = asset_tree.get_block_number().await?;
        self.root = CurveTreeRoot::new(&asset_tree.fetch_root(self.block_number).await?)?;
        Ok(())
    }

    pub async fn track_asset(
        &mut self,
        asset_id: DartAssetId,
        asset_tree: &AssetCurveTreeType,
    ) -> Result<()> {
        if self.track_assets.insert(asset_id) {
            self.update_asset_path(asset_id, asset_tree).await?;
        }
        Ok(())
    }
}

impl CurveTreeLookup<ASSET_TREE_L> for AssetLeafPaths {
    type BlockNumber = BlockNumber;

    fn get_path_to_leaf_index(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<CurveTreePath<ASSET_TREE_L>, DartError> {
        if let Some(path) = self.paths.get(&leaf_index) {
            Ok(path.clone())
        } else {
            Err(DartError::LeafIndexNotFound(leaf_index))
        }
    }

    fn get_path_to_leaf(
        &self,
        leaf: LeafValue<PallasParameters>,
    ) -> Result<CurveTreePath<ASSET_TREE_L>, DartError> {
        let leaf_buf = leaf.encode();
        let leaf_index = self
            .leaf_index
            .get(&leaf_buf)
            .ok_or(DartError::LeafNotFound(leaf))?;
        self.get_path_to_leaf_index(*leaf_index)
    }

    fn params(&self) -> &CurveTreeParameters {
        &CURVE_TREE_PARAMETERS
    }

    fn get_block_number(&self) -> Result<BlockNumber, DartError> {
        Ok(self.block_number)
    }

    fn root_node(&self) -> Result<CurveTreeRoot<ASSET_TREE_L>, DartError> {
        Ok(self.root.clone())
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
    type BlockNumber = BlockNumber;

    async fn new(_height: NodeLevel, _gens_length: usize) -> Result<Self, Self::Error> {
        Err(anyhow::anyhow!(
            "AccountCurveTreeChainStorage does not support new()"
        ))
    }

    async fn parameters(&self) -> &SelRerandParameters<PallasParameters, VestaParameters> {
        &CURVE_TREE_PARAMETERS
    }

    async fn get_block_number(&self) -> Result<BlockNumber, Self::Error> {
        let last_block_number = self
            .api
            .query()
            .dart_asset()
            .account_curve_tree_last_update()
            .await?;
        Ok(last_block_number)
    }

    async fn fetch_root(
        &self,
        block_number: Self::BlockNumber,
    ) -> Result<Root<ACCOUNT_TREE_L, 1, PallasParameters, VestaParameters>> {
        let root = self
            .api
            .query()
            .dart_asset()
            .account_curve_tree_roots(block_number)
            .await?;
        if let Some(root) = root {
            let root: CurveTreeRoot<ACCOUNT_TREE_L> = to_scale(&root);
            Ok(root.decode()?)
        } else {
            Err(anyhow::anyhow!(
                "Root not found for block number {}",
                block_number
            ))
        }
    }

    async fn height(&self) -> NodeLevel {
        ACCOUNT_TREE_HEIGHT
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
}

pub type AccountCurveTreeType = AsyncCurveTreeWithBackend<
    ACCOUNT_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
    AccountCurveTreeChainStorage,
    anyhow::Error,
>;

#[derive(Clone)]
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
