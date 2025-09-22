use core::ops::{Deref, DerefMut};

use polymesh_dart::{
    curve_tree::{
        CompressedCurveTreeRoot, CompressedInner, CurveTreeBackend, CurveTreeConfig,
        CurveTreeParameters, CurveTreeWithBackend, DefaultCurveTreeUpdater, LeafValue,
        NodeLocation, ValidateCurveTreeRoot,
    },
    BlockNumber, LeafIndex, NodeLevel, PallasParameters, VestaParameters, ACCOUNT_TREE_HEIGHT,
    ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_HEIGHT, ASSET_TREE_L, ASSET_TREE_M,
};

pub use polymesh_dart::curve_tree::{AccountTreeConfig, AssetTreeConfig};

pub type AssetLeaf = LeafValue<VestaParameters>;
pub type AssetInnerNode = CompressedInner<ASSET_TREE_M, AssetTreeConfig>;
pub type AssetNodeLocation = NodeLocation<ASSET_TREE_L>;
pub type AssetTreeRoot = CompressedCurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;

pub type AccountLeaf = LeafValue<PallasParameters>;
pub type AccountInnerNode = CompressedInner<ACCOUNT_TREE_M, AccountTreeConfig>;
pub type AccountNodeLocation = NodeLocation<ACCOUNT_TREE_L>;
pub type AccountTreeRoot =
    CompressedCurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;

use super::*;

#[cfg(feature = "std")]
lazy_static::lazy_static! {
    static ref ASSET_CURVE_TREE_PARAMETERS: CurveTreeParameters<AssetTreeConfig> = AssetTreeConfig::build_parameters();
    static ref ACCOUNT_CURVE_TREE_PARAMETERS: CurveTreeParameters<AccountTreeConfig> = AccountTreeConfig::build_parameters();
}

#[cfg(not(feature = "std"))]
static mut ASSET_CURVE_TREE_PARAMETERS: Option<CurveTreeParameters<AssetTreeConfig>> = None;
#[cfg(not(feature = "std"))]
static mut ACCOUNT_CURVE_TREE_PARAMETERS: Option<CurveTreeParameters<AccountTreeConfig>> = None;

impl<T: Config> Pallet<T> {
    #[cfg(feature = "std")]
    pub fn get_asset_curve_tree_parameters() -> &'static CurveTreeParameters<AssetTreeConfig> {
        &ASSET_CURVE_TREE_PARAMETERS
    }

    #[allow(static_mut_refs)]
    #[cfg(not(feature = "std"))]
    pub fn get_asset_curve_tree_parameters() -> &'static CurveTreeParameters<AssetTreeConfig> {
        unsafe {
            if ASSET_CURVE_TREE_PARAMETERS.is_none() {
                let parameters = Self::get_cached_asset_curve_tree_parameters()
                    .expect("Failed to decode curve tree parameters");
                ASSET_CURVE_TREE_PARAMETERS = Some(parameters);
            }
            ASSET_CURVE_TREE_PARAMETERS.as_ref().unwrap()
        }
    }

    #[cfg(feature = "std")]
    pub fn get_account_curve_tree_parameters() -> &'static CurveTreeParameters<AccountTreeConfig> {
        &ACCOUNT_CURVE_TREE_PARAMETERS
    }

    #[allow(static_mut_refs)]
    #[cfg(not(feature = "std"))]
    pub fn get_account_curve_tree_parameters() -> &'static CurveTreeParameters<AccountTreeConfig> {
        unsafe {
            if ACCOUNT_CURVE_TREE_PARAMETERS.is_none() {
                let parameters = AccountTreeConfig::build_parameters();
                ACCOUNT_CURVE_TREE_PARAMETERS = Some(parameters);
            }
            ACCOUNT_CURVE_TREE_PARAMETERS.as_ref().unwrap()
        }
    }

    pub fn get_cached_asset_curve_tree_parameters() -> Option<CurveTreeParameters<AssetTreeConfig>>
    {
        CachedAssetCurveTreeParameters::<T>::get().and_then(|p| p.decode::<AssetTreeConfig>().ok())
    }

    pub fn get_cached_account_curve_tree_parameters(
    ) -> Option<CurveTreeParameters<AccountTreeConfig>> {
        CachedAccountCurveTreeParameters::<T>::get()
            .and_then(|p| p.decode::<AccountTreeConfig>().ok())
    }
}

fn get_block_number<T: Config>() -> Result<BlockNumberFor<T>, Error<T>> {
    Ok(frame_system::Pallet::<T>::block_number())
}

/// Asset Curve Tree Storage backend.
#[derive(Clone)]
pub struct AssetCurveTreeStorage<T: Config> {
    _marker: core::marker::PhantomData<T>,
}

impl<T: Config> CurveTreeBackend<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>
    for AssetCurveTreeStorage<T>
{
    type Error = Error<T>;
    type Updater = DefaultCurveTreeUpdater<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>;

    fn new(_height: NodeLevel, _gens_length: usize) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: core::marker::PhantomData,
        })
    }

    fn parameters(&self) -> &CurveTreeParameters<AssetTreeConfig> {
        Pallet::<T>::get_asset_curve_tree_parameters()
    }

    fn get_block_number(&self) -> Result<BlockNumber, Self::Error> {
        // Return the current block number from the storage.
        Ok(get_block_number::<T>()?.try_into().unwrap_or_default())
    }

    fn store_root(
        &mut self,
        root: CompressedCurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>,
    ) -> Result<BlockNumber, Self::Error> {
        let block_number = get_block_number::<T>()?;

        // Store the root in the storage.
        AssetCurveTreeRoots::<T>::insert(block_number, &root);

        // Store the block number for the asset curve tree update.
        AssetCurveTreeLastUpdate::<T>::put(block_number);

        // Emit an event for the asset curve tree root update.
        Pallet::<T>::deposit_event(Event::<T>::AssetCurveTreeRootUpdated { root });

        Ok(block_number.try_into().unwrap_or_default())
    }

    fn fetch_root(
        &self,
        block_number: BlockNumber,
    ) -> Result<CompressedCurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>, Self::Error>
    {
        let block_number: BlockNumberFor<T> = block_number.into();
        // Fetch the root from the storage.
        let root =
            AssetCurveTreeRoots::<T>::get(block_number).ok_or(Error::<T>::CurveTreeRootNotFound)?;
        Ok(root)
    }

    fn height(&self) -> NodeLevel {
        ASSET_TREE_HEIGHT
    }

    fn set_height(&mut self, _height: NodeLevel) -> Result<(), Self::Error> {
        Ok(())
    }

    fn allocate_leaf_index(&mut self) -> LeafIndex {
        let leaf_index = AssetLeaves::<T>::count() as LeafIndex;
        leaf_index
    }

    fn get_leaf(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Option<LeafValue<VestaParameters>>, Self::Error> {
        let leaf = AssetLeaves::<T>::get(leaf_index);
        Ok(leaf)
    }

    fn set_leaf(
        &mut self,
        leaf_index: LeafIndex,
        new_leaf_value: LeafValue<VestaParameters>,
    ) -> Result<Option<LeafValue<VestaParameters>>, Self::Error> {
        // Use `mutate` to update the leaf value in the storage and return the previous value.
        Ok(AssetLeaves::<T>::mutate(leaf_index, |leaf| {
            // Get the old value, if it exists.
            let previous_value = leaf.take();
            // Set the new value.
            *leaf = Some(new_leaf_value);
            previous_value
        }))
    }

    fn leaf_count(&self) -> LeafIndex {
        AssetLeaves::<T>::count() as LeafIndex
    }

    fn get_inner_node(
        &self,
        location: NodeLocation<ASSET_TREE_L>,
    ) -> Result<Option<AssetInnerNode>, Self::Error> {
        Ok(AssetInnerNodes::<T>::get(location))
    }

    fn set_inner_node(
        &mut self,
        location: NodeLocation<ASSET_TREE_L>,
        new_node: AssetInnerNode,
    ) -> Result<(), Self::Error> {
        // set the inner node in the storage.
        AssetInnerNodes::<T>::insert(location, new_node);
        Ok(())
    }
}

/// Account Curve Tree Storage backend.
#[derive(Clone)]
pub struct AccountCurveTreeStorage<T: Config> {
    _marker: core::marker::PhantomData<T>,
}

impl<T: Config> CurveTreeBackend<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>
    for AccountCurveTreeStorage<T>
{
    type Error = Error<T>;
    type Updater = DefaultCurveTreeUpdater<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>;

    fn new(_height: NodeLevel, _gens_length: usize) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: core::marker::PhantomData,
        })
    }

    fn parameters(&self) -> &CurveTreeParameters<AccountTreeConfig> {
        Pallet::<T>::get_account_curve_tree_parameters()
    }

    fn get_block_number(&self) -> Result<BlockNumber, Self::Error> {
        // Return the current block number from the storage.
        Ok(get_block_number::<T>()?.try_into().unwrap_or_default())
    }

    fn store_root(
        &mut self,
        root: CompressedCurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>,
    ) -> Result<BlockNumber, Self::Error> {
        let block_number: BlockNumberFor<T> = get_block_number::<T>()?.into();
        // Store the root in the storage.
        AccountCurveTreeRoots::<T>::insert(block_number, &root);

        // Store the block number for the account curve tree update.
        AccountCurveTreeLastUpdate::<T>::put(block_number);

        // Emit an event for the account curve tree root update.
        Pallet::<T>::deposit_event(Event::<T>::AccountCurveTreeRootUpdated { root });

        Ok(block_number.try_into().unwrap_or_default())
    }

    fn fetch_root(
        &self,
        block_number: BlockNumber,
    ) -> Result<
        CompressedCurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>,
        Self::Error,
    > {
        let block_number: BlockNumberFor<T> = block_number.into();
        // Fetch the root from the storage.
        let root = AccountCurveTreeRoots::<T>::get(block_number)
            .ok_or(Error::<T>::CurveTreeRootNotFound)?;
        Ok(root)
    }

    fn height(&self) -> NodeLevel {
        ACCOUNT_TREE_HEIGHT
    }

    fn set_height(&mut self, _height: NodeLevel) -> Result<(), Self::Error> {
        Ok(())
    }

    fn allocate_leaf_index(&mut self) -> LeafIndex {
        Pallet::<T>::next_account_leaf_index()
    }

    fn batch_inserts_supported(&self) -> bool {
        true
    }

    fn last_committed_leaf_index(&self) -> Result<LeafIndex, Self::Error> {
        let leaf_index = LastCommittedAccountLeafIndex::<T>::get();
        Ok(leaf_index)
    }

    fn set_committed_leaf_index(&mut self, leaf_index: LeafIndex) -> Result<(), Self::Error> {
        LastCommittedAccountLeafIndex::<T>::put(leaf_index);
        Ok(())
    }

    fn get_leaf(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
        match AccountLeaves::<T>::get(leaf_index) {
            Some(commitment) => Ok(Some(commitment.as_leaf_value()?)),
            None => Ok(None),
        }
    }

    fn set_leaf(
        &mut self,
        leaf_index: LeafIndex,
        new_leaf_value: LeafValue<PallasParameters>,
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
        let account_commitment = AccountStateCommitment::from_affine(*new_leaf_value.deref())?;
        // Use `mutate` to update the leaf value in the storage and return the previous value.
        AccountLeaves::<T>::set(leaf_index, Some(account_commitment));

        // The account curve tree is append-only, so we don't support updating existing leaves.
        Ok(None)
    }

    fn leaf_count(&self) -> LeafIndex {
        NextAccountLeafIndex::<T>::get() as LeafIndex
    }

    fn get_inner_node(
        &self,
        location: NodeLocation<ACCOUNT_TREE_L>,
    ) -> Result<Option<AccountInnerNode>, Self::Error> {
        Ok(AccountInnerNodes::<T>::get(location))
    }

    fn set_inner_node(
        &mut self,
        location: NodeLocation<ACCOUNT_TREE_L>,
        new_node: AccountInnerNode,
    ) -> Result<(), Self::Error> {
        // set the inner node in the storage.
        AccountInnerNodes::<T>::insert(location, new_node);
        Ok(())
    }
}

pub type AssetCurveTreeType<T> = CurveTreeWithBackend<
    ASSET_TREE_L,
    ASSET_TREE_M,
    AssetTreeConfig,
    AssetCurveTreeStorage<T>,
    Error<T>,
>;

pub struct AssetCurveTree<T: Config>(AssetCurveTreeType<T>);

impl<T: Config> Deref for AssetCurveTree<T> {
    type Target = AssetCurveTreeType<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Config> DerefMut for AssetCurveTree<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Config> AssetCurveTree<T> {
    pub fn new(height: NodeLevel, gens_length: usize) -> Result<Self, Error<T>> {
        Ok(Self(CurveTreeWithBackend::new_no_init(
            height,
            gens_length,
        )?))
    }
}

impl<T: Config> ValidateCurveTreeRoot<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig>
    for &AssetCurveTree<T>
{
    fn get_block_root(&self, block: BlockNumber) -> Option<AssetTreeRoot> {
        let block: BlockNumberFor<T> = block.into();
        AssetCurveTreeRoots::<T>::get(block)
    }

    fn params(&self) -> &CurveTreeParameters<AssetTreeConfig> {
        self.0.parameters()
    }
}

pub type AccountCurveTreeType<T> = CurveTreeWithBackend<
    ACCOUNT_TREE_L,
    ACCOUNT_TREE_M,
    AccountTreeConfig,
    AccountCurveTreeStorage<T>,
    Error<T>,
>;

pub struct AccountCurveTree<T: Config>(AccountCurveTreeType<T>);

impl<T: Config> Deref for AccountCurveTree<T> {
    type Target = AccountCurveTreeType<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Config> DerefMut for AccountCurveTree<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Config> AccountCurveTree<T> {
    pub fn new(height: NodeLevel, gens_length: usize) -> Result<Self, Error<T>> {
        Ok(Self(CurveTreeWithBackend::new_no_init(
            height,
            gens_length,
        )?))
    }
}

impl<T: Config> ValidateCurveTreeRoot<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig>
    for &AccountCurveTree<T>
{
    fn get_block_root(&self, block: BlockNumber) -> Option<AccountTreeRoot> {
        let block: BlockNumberFor<T> = block.into();
        AccountCurveTreeRoots::<T>::get(block)
    }

    fn params(&self) -> &CurveTreeParameters<AccountTreeConfig> {
        self.parameters()
    }
}
