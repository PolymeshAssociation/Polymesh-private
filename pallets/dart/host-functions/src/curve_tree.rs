use core::marker::PhantomData;

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use polymesh_dart::curve_tree::SingleLayerParameters;
use sp_runtime_interface::pass_by::{Codec, PassBy};

use ark_ec::short_weierstrass::Affine;
#[cfg(feature = "std")]
use ark_ec::short_weierstrass::SWCurveConfig;
#[cfg(not(feature = "std"))]
use polymesh_dart::{
    ACCOUNT_TREE_L, ACCOUNT_TREE_M, ASSET_TREE_L, ASSET_TREE_M,
    curve_tree::{AccountTreeConfig, AssetTreeConfig},
};
use polymesh_dart::{
    ChildIndex, CompressedAffine, Error as DartError,
    curve_tree::{
        CompressedChildCommitments, CompressedInner, CompressedXCoords, CurveTreeConfig,
        CurveTreeUpdater, Inner, update_inner_node,
    },
    encode::CompressedBaseField,
};

use crate::Error;

#[derive(Clone, Encode, Decode)]
pub struct UpdateTreeNodeRequest<const L: usize, const M: usize, C: CurveTreeConfig> {
    is_even: bool,
    commitments: [CompressedAffine; M],
    local_index: ChildIndex,
    old_child: Option<CompressedChildCommitments<M>>,
    new_child: CompressedChildCommitments<M>,
    #[codec(skip)]
    _marker: PhantomData<C>,
}

impl<const L: usize, const M: usize, C: CurveTreeConfig> PassBy for UpdateTreeNodeRequest<L, M, C> {
    type PassBy = Codec<Self>;
}

#[cfg(feature = "std")]
impl<const L: usize, const M: usize, C: CurveTreeConfig> UpdateTreeNodeRequest<L, M, C> {
    pub fn update(self) -> Result<UpdateTreeNodeResult<M>, Error> {
        let params = C::parameters();

        let res = if self.is_even {
            self.update_inner_node::<C::P1, C::P0>(
                &params.odd_parameters.delta,
                &params.even_parameters,
            )
        } else {
            self.update_inner_node::<C::P0, C::P1>(
                &params.even_parameters.delta,
                &params.odd_parameters,
            )
        };

        res.map_err(|_| Error::DecodingFailed)
    }

    fn update_inner_node<
        P0: SWCurveConfig + Copy + Send,
        P1: SWCurveConfig<BaseField = P0::ScalarField, ScalarField = P0::BaseField> + Copy + Send,
    >(
        self,
        delta: &Affine<P0>,
        parameters: &SingleLayerParameters<P1>,
    ) -> Result<UpdateTreeNodeResult<M>, DartError> {
        // Decompress commitments
        let mut commitments = [Default::default(); M];
        for (c, cc) in commitments.iter_mut().zip(self.commitments.iter()) {
            *c = cc.try_into()?;
        }

        // Decompress child new and old value.
        let old_child = match self.old_child {
            Some(c) => Some(c.decompress()?),
            None => None,
        };
        let new_child = self.new_child.decompress()?;

        // Update the node.
        let new_x_coords = update_inner_node::<L, M, P0, P1>(
            &mut commitments,
            self.local_index,
            old_child,
            new_child,
            delta,
            parameters,
        )?;

        let mut results = UpdateTreeNodeResult::default();
        // Compress the updated commitments
        for (r, c) in results.commitments.iter_mut().zip(commitments.into_iter()) {
            *r = c.try_into()?;
        }
        // Compress the x_coords
        for (r, x) in results.x_cords.iter_mut().zip(new_x_coords.into_iter()) {
            *r = CompressedBaseField::from_base_field(&x)?;
        }
        Ok(results)
    }
}

#[cfg(not(feature = "std"))]
impl UpdateTreeNodeRequest<ASSET_TREE_L, ASSET_TREE_M, AssetTreeConfig> {
    pub fn update(self) -> Result<UpdateTreeNodeResult<ASSET_TREE_M>, Error> {
        crate::native_dart_assets::asset_tree_update_inner_node(self)
    }
}

#[cfg(not(feature = "std"))]
impl UpdateTreeNodeRequest<ACCOUNT_TREE_L, ACCOUNT_TREE_M, AccountTreeConfig> {
    pub fn update(self) -> Result<UpdateTreeNodeResult<ACCOUNT_TREE_M>, Error> {
        crate::native_dart_assets::account_tree_update_inner_node(self)
    }
}

#[derive(Clone, Encode, Decode)]
pub struct UpdateTreeNodeResult<const M: usize> {
    commitments: [CompressedAffine; M],
    x_cords: [CompressedBaseField; M],
}

impl<const M: usize> Default for UpdateTreeNodeResult<M> {
    fn default() -> Self {
        Self {
            commitments: [Default::default(); M],
            x_cords: [Default::default(); M],
        }
    }
}

/// Curve tree updater that helps updating the tree root when a leaf is added or updated.
#[derive(Clone, Encode, Decode)]
pub struct HostCurveTreeUpdater<const L: usize, const M: usize, C: CurveTreeConfig> {
    _marker: PhantomData<C>,
}

impl<const L: usize, const M: usize, C: CurveTreeConfig> HostCurveTreeUpdater<L, M, C> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<const L: usize, const M: usize, C: CurveTreeConfig> CurveTreeUpdater<L, M, C>
    for HostCurveTreeUpdater<L, M, C>
{
    fn update_node(
        inner: &mut CompressedInner<M, C>,
        child_index: ChildIndex,
        old_child: Option<CompressedChildCommitments<M>>,
        new_child: CompressedChildCommitments<M>,
    ) -> Result<CompressedXCoords<M>, DartError> {
        let params = C::parameters();

        let mut tmp_inner = inner.decompress()?;
        let new_x_coords = match &mut tmp_inner {
            Inner::Even(commitments) => {
                // Decompress the old and new child commitments.
                let old_child = old_child.map(|c| c.decompress::<C::P1>()).transpose()?;
                let new_child = new_child.decompress::<C::P1>()?;

                // Update the node.
                let new_x_coords = update_inner_node::<L, M, C::P1, C::P0>(
                    commitments,
                    child_index,
                    old_child,
                    new_child,
                    &params.odd_parameters.delta,
                    &params.even_parameters,
                )?;

                CompressedXCoords::compress::<C::P1>(&new_x_coords)?
            }
            Inner::Odd(commitments) => {
                // Decompress the old and new child commitments.
                let old_child = old_child.map(|c| c.decompress::<C::P0>()).transpose()?;
                let new_child = new_child.decompress::<C::P0>()?;

                // Update the node.
                let new_x_coords = update_inner_node::<L, M, C::P0, C::P1>(
                    commitments,
                    child_index,
                    old_child,
                    new_child,
                    &params.even_parameters.delta,
                    &params.odd_parameters,
                )?;

                CompressedXCoords::compress::<C::P0>(&new_x_coords)?
            }
        };

        // Update the compressed inner node.
        *inner = CompressedInner::compress(&tmp_inner)?;

        Ok(new_x_coords)
    }
}
