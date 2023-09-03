use polymesh_primitives::{BlockNumber, Moment};

#[cfg(feature = "ci-runtime")]
pub const MILLISECS_PER_BLOCK: Moment = 500;
#[cfg(not(feature = "ci-runtime"))]
pub const MILLISECS_PER_BLOCK: Moment = 6000;
#[cfg(feature = "ci-runtime")]
pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = MINUTES;
#[cfg(not(feature = "ci-runtime"))]
pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 30 * MINUTES;

// These time units are defined in number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
