// filled in W2
use revolt_result::Result;

use crate::{Database, TakedownRequest};

/// What a reviewer chose to remove
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalPlan {
    /// Indexes into `TakedownRequest.targets`
    pub targets: Vec<usize>,
    pub whole_message: bool,
    pub include_copies: bool,
    pub block_reuploads: bool,
}

/// What a removal did
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemovalOutcome {
    pub removed_files: Vec<String>,
    pub deleted_messages: Vec<String>,
    pub copies: u64,
    pub blocked_keys: Vec<String>,
    pub uploader_ids: Vec<String>,
}

/// How many identical copies a removal would also take down
pub async fn plan_copy_count(
    db: &Database,
    request: &TakedownRequest,
    plan: &RemovalPlan,
) -> Result<u64> {
    let _ = (db, request, plan);
    Err(create_error!(NotFound))
}

/// Carry out a removal
pub async fn execute_removal(
    db: &Database,
    request: &mut TakedownRequest,
    plan: &RemovalPlan,
    actor: &str,
) -> Result<RemovalOutcome> {
    let _ = (db, request, plan, actor);
    Err(create_error!(NotFound))
}
