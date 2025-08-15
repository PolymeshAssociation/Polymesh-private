use core::ops::{Deref, DerefMut};

use polymesh_dart::{
    curve_tree::{
        CurveTreeBackend, CurveTreeParameters, CurveTreeRoot, CurveTreeWithBackend, Inner,
        LeafValue, NodeLocation, Root, ValidateCurveTreeRoot,
    },
    LeafIndex, NodeLevel, PallasParameters, VestaParameters, ACCOUNT_TREE_HEIGHT, ACCOUNT_TREE_L,
    ASSET_TREE_HEIGHT, ASSET_TREE_L,
};
pub type AssetLeaf = LeafValue<PallasParameters>;
pub type AssetInnerNode = Inner<1, PallasParameters, VestaParameters>;
pub type AssetNodeLocation = NodeLocation<ASSET_TREE_L>;

pub type AccountLeaf = LeafValue<PallasParameters>;
pub type AccountInnerNode = Inner<1, PallasParameters, VestaParameters>;
pub type AccountNodeLocation = NodeLocation<ACCOUNT_TREE_L>;

use super::*;

#[cfg(feature = "std")]
lazy_static::lazy_static! {
    static ref CURVE_TREE_PARAMETERS: CurveTreeParameters = CurveTreeParameters::new(
        polymesh_dart::MAX_CURVE_TREE_GENS,
        polymesh_dart::MAX_CURVE_TREE_GENS,
    ).expect("Failed to create curve tree parameters");
}

#[cfg(not(feature = "std"))]
static mut CURVE_TREE_PARAMETERS: Option<CurveTreeParameters> = None;

impl<T: Config> Pallet<T> {
    #[cfg(feature = "std")]
    pub fn get_curve_tree_parameters() -> &'static CurveTreeParameters {
        &CURVE_TREE_PARAMETERS
    }

    #[allow(static_mut_refs)]
    #[cfg(not(feature = "std"))]
    pub fn get_curve_tree_parameters() -> &'static CurveTreeParameters {
        unsafe {
            if CURVE_TREE_PARAMETERS.is_none() {
                let parameters = Self::get_cached_curve_tree_parameters()
                    .expect("Failed to decode curve tree parameters");
                CURVE_TREE_PARAMETERS = Some(parameters);
            }
            CURVE_TREE_PARAMETERS.as_ref().unwrap()
        }
    }

    pub fn get_cached_curve_tree_parameters() -> Option<CurveTreeParameters> {
        CachedCurveTreeParameters::<T>::get().and_then(|p| p.decode().ok())
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

impl<T: Config> CurveTreeBackend<ASSET_TREE_L, 1, PallasParameters, VestaParameters>
    for AssetCurveTreeStorage<T>
{
    type Error = Error<T>;
    type BlockNumber = BlockNumberFor<T>;

    fn new(_height: NodeLevel, _gens_length: usize) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: core::marker::PhantomData,
        })
    }

    fn parameters(&self) -> &CurveTreeParameters {
        Pallet::<T>::get_curve_tree_parameters()
    }

    fn get_block_number(&self) -> Result<Self::BlockNumber, Self::Error> {
        // Return the current block number from the storage.
        get_block_number::<T>()
    }

    fn store_root(
        &mut self,
        root: Root<ASSET_TREE_L, 1, PallasParameters, VestaParameters>,
    ) -> Result<Self::BlockNumber, Self::Error> {
        let block_number = get_block_number::<T>()?;

        // Store the root in the storage.
        let root = CurveTreeRoot::new(&root)?;
        AssetCurveTreeRoots::<T>::insert(block_number, &root);

        // Store the block number for the asset curve tree update.
        AssetCurveTreeLastUpdate::<T>::put(block_number);

        // Emit an event for the asset curve tree root update.
        Pallet::<T>::deposit_event(Event::<T>::AssetCurveTreeRootUpdated { root });

        Ok(block_number)
    }

    fn fetch_root(
        &self,
        block_number: Self::BlockNumber,
    ) -> Result<Root<ASSET_TREE_L, 1, PallasParameters, VestaParameters>, Self::Error> {
        let block_number: BlockNumberFor<T> = block_number.into();
        // Fetch the root from the storage.
        let root =
            AssetCurveTreeRoots::<T>::get(block_number).ok_or(Error::<T>::CurveTreeRootNotFound)?;
        Ok(root.decode()?)
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
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
        let leaf = AssetLeaves::<T>::get(leaf_index);
        Ok(leaf)
    }

    fn set_leaf(
        &mut self,
        leaf_index: LeafIndex,
        new_leaf_value: LeafValue<PallasParameters>,
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
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
    ) -> Result<Option<Inner<1, PallasParameters, VestaParameters>>, Self::Error> {
        Ok(AssetInnerNodes::<T>::get(location))
    }

    fn set_inner_node(
        &mut self,
        location: NodeLocation<ASSET_TREE_L>,
        new_node: Inner<1, PallasParameters, VestaParameters>,
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

impl<T: Config> CurveTreeBackend<ACCOUNT_TREE_L, 1, PallasParameters, VestaParameters>
    for AccountCurveTreeStorage<T>
{
    type Error = Error<T>;
    type BlockNumber = BlockNumberFor<T>;

    fn new(_height: NodeLevel, _gens_length: usize) -> Result<Self, Self::Error> {
        Ok(Self {
            _marker: core::marker::PhantomData,
        })
    }

    fn parameters(&self) -> &CurveTreeParameters {
        Pallet::<T>::get_curve_tree_parameters()
    }

    fn get_block_number(&self) -> Result<Self::BlockNumber, Self::Error> {
        // Return the current block number from the storage.
        get_block_number::<T>()
    }

    fn store_root(
        &mut self,
        root: Root<ACCOUNT_TREE_L, 1, PallasParameters, VestaParameters>,
    ) -> Result<Self::BlockNumber, Self::Error> {
        let block_number = get_block_number::<T>()?;
        // Store the root in the storage.
        let root = CurveTreeRoot::new(&root)?;
        AccountCurveTreeRoots::<T>::insert(block_number, &root);

        // Store the block number for the account curve tree update.
        AccountCurveTreeLastUpdate::<T>::put(block_number);

        // Emit an event for the account curve tree root update.
        Pallet::<T>::deposit_event(Event::<T>::AccountCurveTreeRootUpdated { root });

        Ok(block_number)
    }

    fn fetch_root(
        &self,
        block_number: Self::BlockNumber,
    ) -> Result<Root<ACCOUNT_TREE_L, 1, PallasParameters, VestaParameters>, Self::Error> {
        let block_number: BlockNumberFor<T> = block_number.into();
        // Fetch the root from the storage.
        let root = AccountCurveTreeRoots::<T>::get(block_number)
            .ok_or(Error::<T>::CurveTreeRootNotFound)?;
        Ok(root.decode()?)
    }

    fn height(&self) -> NodeLevel {
        ACCOUNT_TREE_HEIGHT
    }

    fn set_height(&mut self, _height: NodeLevel) -> Result<(), Self::Error> {
        Ok(())
    }

    fn allocate_leaf_index(&mut self) -> LeafIndex {
        let leaf_index = NextAccountLeafIndex::<T>::get();
        // Increment the next leaf index for the next call.
        NextAccountLeafIndex::<T>::put(leaf_index + 1);
        leaf_index
    }

    fn get_leaf(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
        let leaf = AccountLeaves::<T>::get(leaf_index);
        Ok(leaf)
    }

    fn set_leaf(
        &mut self,
        leaf_index: LeafIndex,
        new_leaf_value: LeafValue<PallasParameters>,
    ) -> Result<Option<LeafValue<PallasParameters>>, Self::Error> {
        // Use `mutate` to update the leaf value in the storage and return the previous value.
        Ok(AccountLeaves::<T>::mutate(leaf_index, |leaf| {
            // Get the old value, if it exists.
            let previous_value = leaf.take();
            // Set the new value.
            *leaf = Some(new_leaf_value);
            previous_value
        }))
    }

    fn leaf_count(&self) -> LeafIndex {
        NextAccountLeafIndex::<T>::get() as LeafIndex
    }

    fn get_inner_node(
        &self,
        location: NodeLocation<ACCOUNT_TREE_L>,
    ) -> Result<Option<Inner<1, PallasParameters, VestaParameters>>, Self::Error> {
        Ok(AccountInnerNodes::<T>::get(location))
    }

    fn set_inner_node(
        &mut self,
        location: NodeLocation<ACCOUNT_TREE_L>,
        new_node: Inner<1, PallasParameters, VestaParameters>,
    ) -> Result<(), Self::Error> {
        // set the inner node in the storage.
        AccountInnerNodes::<T>::insert(location, new_node);
        Ok(())
    }
}

pub type AssetCurveTreeType<T> = CurveTreeWithBackend<
    ASSET_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
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

impl<T: Config> ValidateCurveTreeRoot<ASSET_TREE_L> for &AssetCurveTree<T> {
    type BlockNumber = BlockNumberFor<T>;

    fn get_block_root(&self, block: BlockNumberFor<T>) -> Option<CurveTreeRoot<ASSET_TREE_L>> {
        AssetCurveTreeRoots::<T>::get(block)
    }

    fn params(&self) -> &CurveTreeParameters {
        self.parameters()
    }
}

pub type AccountCurveTreeType<T> = CurveTreeWithBackend<
    ACCOUNT_TREE_L,
    1,
    PallasParameters,
    VestaParameters,
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

impl<T: Config> ValidateCurveTreeRoot<ACCOUNT_TREE_L> for &AccountCurveTree<T> {
    type BlockNumber = BlockNumberFor<T>;

    fn get_block_root(&self, block: BlockNumberFor<T>) -> Option<CurveTreeRoot<ACCOUNT_TREE_L>> {
        AccountCurveTreeRoots::<T>::get(block)
    }

    fn params(&self) -> &CurveTreeParameters {
        self.parameters()
    }
}
