//! TSP relationship state machine.

use crate::error::Result;
use crate::types::{RelationshipStatus, ThreadId};

/// Manages relationship state transitions.
pub struct RelationshipManager;

impl RelationshipManager {
    /// Initiate a relationship (local VID proposes to remote).
    pub fn initiate(thread_id: ThreadId) -> Result<RelationshipStatus> {
        Ok(RelationshipStatus::Unidirectional { thread_id })
    }

    /// Accept an initiated relationship (upgrade unidirectional to bidirectional).
    pub fn accept(
        current: &RelationshipStatus,
        thread_id: &ThreadId,
    ) -> Result<RelationshipStatus> {
        match current {
            RelationshipStatus::Unidirectional {
                thread_id: current_id,
            } => {
                if current_id != thread_id {
                    return Err(crate::error::TspError::ThreadIdMismatch);
                }
                Ok(RelationshipStatus::Bidirectional {
                    thread_id: thread_id.clone(),
                    outstanding_nested_thread_ids: Vec::new(),
                })
            }
            RelationshipStatus::ReverseUnidirectional {
                thread_id: current_id,
            } => {
                if current_id != thread_id {
                    return Err(crate::error::TspError::ThreadIdMismatch);
                }
                Ok(RelationshipStatus::Bidirectional {
                    thread_id: thread_id.clone(),
                    outstanding_nested_thread_ids: Vec::new(),
                })
            }
            _ => Err(crate::error::TspError::Relationship(
                "Cannot accept from current state".into(),
            )),
        }
    }

    /// Cancel a relationship (revert to unrelated).
    pub fn cancel(current: &RelationshipStatus) -> Result<RelationshipStatus> {
        match current {
            RelationshipStatus::Unidirectional { .. }
            | RelationshipStatus::ReverseUnidirectional { .. }
            | RelationshipStatus::Bidirectional { .. } => Ok(RelationshipStatus::Unrelated),
            RelationshipStatus::Unrelated => Err(crate::error::TspError::Relationship(
                "No relationship to cancel".into(),
            )),
        }
    }

    /// Add a pending nested thread ID to a bidirectional relationship.
    pub fn add_nested_thread_id(
        status: &mut RelationshipStatus,
        thread_id: ThreadId,
    ) -> Result<()> {
        match status {
            RelationshipStatus::Bidirectional {
                outstanding_nested_thread_ids,
                ..
            } => {
                outstanding_nested_thread_ids.push(thread_id);
                Ok(())
            }
            _ => Err(crate::error::TspError::Relationship(
                "Cannot add nested thread to non-bidirectional relationship".into(),
            )),
        }
    }

    /// Remove a pending nested thread ID.
    pub fn remove_nested_thread_id(
        status: &mut RelationshipStatus,
        thread_id: &ThreadId,
    ) -> Result<()> {
        match status {
            RelationshipStatus::Bidirectional {
                outstanding_nested_thread_ids,
                ..
            } => {
                if let Some(pos) = outstanding_nested_thread_ids
                    .iter()
                    .position(|t| t == thread_id)
                {
                    outstanding_nested_thread_ids.remove(pos);
                    Ok(())
                } else {
                    Err(crate::error::TspError::Relationship(
                        "Thread ID not found".into(),
                    ))
                }
            }
            _ => Err(crate::error::TspError::Relationship(
                "No nested threads in current relationship state".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relationship_initiate() {
        let thread_id = b"test-thread".to_vec();
        let status = RelationshipManager::initiate(thread_id.clone()).unwrap();
        assert!(matches!(status, RelationshipStatus::Unidirectional { .. }));
    }

    #[test]
    fn test_relationship_accept() {
        let thread_id = b"test-thread".to_vec();
        let initial = RelationshipStatus::Unidirectional {
            thread_id: thread_id.clone(),
        };

        let accepted = RelationshipManager::accept(&initial, &thread_id).unwrap();
        assert!(matches!(accepted, RelationshipStatus::Bidirectional { .. }));
    }

    #[test]
    fn test_relationship_cancel() {
        let thread_id = b"test-thread".to_vec();
        let status = RelationshipStatus::Bidirectional {
            thread_id,
            outstanding_nested_thread_ids: Vec::new(),
        };

        let cancelled = RelationshipManager::cancel(&status).unwrap();
        assert_eq!(cancelled, RelationshipStatus::Unrelated);
    }
}
