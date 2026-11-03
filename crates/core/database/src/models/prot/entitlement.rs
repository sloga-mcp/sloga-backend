//! S5b predicates on S1's channel entitlement (contracts 6.1). An inherent
//! `impl` outside S1's file, so S1's model is not edited. The stage -> state
//! table every S5 transaction writes is `stage_entitlement_state`
//! (`tank_model.rs`, exported with the other planners).

use crate::ChannelEntitlementState;

impl crate::ChannelEntitlement {
    /// New seats may be claimed (protect, seat claims): Active only. Identical to S1's `is_active()`, which the
    /// planner (`model.rs:829`) and protect (`ops/mongodb.rs:737`, `ops/reference.rs:314`) keep calling.
    pub fn allows_new_seats(&self) -> bool {
        self.is_active()
    }

    /// Text traffic (Text group create incl. successors, Adds of seated members' devices, join intents, KeyPackage
    /// claims, encrypted sends): Active or Grace (D14)
    pub fn allows_text_traffic(&self) -> bool {
        matches!(
            self.state,
            ChannelEntitlementState::Active | ChannelEntitlementState::Grace
        )
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;
    use revolt_models::v0;

    use super::super::tank_model::stage_entitlement_state;
    use crate::{ChannelEntitlement, ChannelEntitlementSource, ChannelEntitlementState};

    const STATES: [ChannelEntitlementState; 4] = [
        ChannelEntitlementState::Active,
        ChannelEntitlementState::Grace,
        ChannelEntitlementState::Frozen,
        ChannelEntitlementState::Deleted,
    ];

    fn entitlement(state: ChannelEntitlementState) -> ChannelEntitlement {
        ChannelEntitlement {
            id: "01ENTITLEMENT".to_string(),
            channel_id: "01CHANNEL".to_string(),
            server_id: "01SERVER".to_string(),
            source: ChannelEntitlementSource::Crowdfund,
            slot_cap: 10,
            device_cap: None,
            state,
            granted_by: "01OWNER".to_string(),
            created_at: Timestamp::UNIX_EPOCH,
        }
    }

    #[test]
    fn allows_new_seats_equals_is_active() {
        for state in STATES {
            let entitlement = entitlement(state.clone());
            assert_eq!(
                entitlement.allows_new_seats(),
                entitlement.is_active(),
                "{state:?}"
            );
            assert_eq!(
                entitlement.allows_new_seats(),
                state == ChannelEntitlementState::Active,
                "{state:?}"
            );
        }
    }

    #[test]
    fn allows_text_traffic_is_active_or_grace() {
        for state in STATES {
            let expected = matches!(
                state,
                ChannelEntitlementState::Active | ChannelEntitlementState::Grace
            );
            assert_eq!(
                entitlement(state.clone()).allows_text_traffic(),
                expected,
                "{state:?}"
            );
        }
        // the source does not matter
        let mut grant = entitlement(ChannelEntitlementState::Grace);
        grant.source = ChannelEntitlementSource::AdminGrant;
        assert!(grant.allows_text_traffic());
        assert!(!grant.allows_new_seats());
    }

    /// The 6.1 table: Terminated is a Deleted tombstone (BR4), Settling stops
    /// traffic, Launching is Active
    #[test]
    fn tank_stages_map_to_entitlement_states() {
        let table = [
            (
                v0::ProtTankStage::Launching,
                ChannelEntitlementState::Active,
            ),
            (v0::ProtTankStage::Active, ChannelEntitlementState::Active),
            (v0::ProtTankStage::Grace, ChannelEntitlementState::Grace),
            (v0::ProtTankStage::Frozen, ChannelEntitlementState::Frozen),
            (v0::ProtTankStage::Settling, ChannelEntitlementState::Frozen),
            (v0::ProtTankStage::Deleted, ChannelEntitlementState::Deleted),
            (
                v0::ProtTankStage::Terminated,
                ChannelEntitlementState::Deleted,
            ),
        ];
        for (stage, state) in &table {
            assert_eq!(&stage_entitlement_state(*stage), state, "{stage:?}");
        }

        // no stage but Launching/Active admits a seat
        for (stage, _) in table {
            let written = entitlement(stage_entitlement_state(stage));
            let launched_or_active = matches!(
                stage,
                v0::ProtTankStage::Launching | v0::ProtTankStage::Active
            );
            assert_eq!(written.allows_new_seats(), launched_or_active, "{stage:?}");
        }
    }
}
