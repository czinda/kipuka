//! HSM slot and session management.

use crate::error::{HsmError, HsmResult};
use crate::pkcs11::Pkcs11Context;
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

/// HSM slot with session management.
pub struct HsmSlot {
    context: Pkcs11Context,
    slot: Slot,
}

impl HsmSlot {
    /// Create a new HSM slot.
    ///
    /// # Arguments
    ///
    /// * `context` - PKCS#11 library context
    /// * `slot` - Slot identifier
    pub fn new(context: Pkcs11Context, slot: Slot) -> Self {
        Self { context, slot }
    }

    /// Get the slot identifier.
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Get slot information description.
    pub fn slot_info(&self) -> HsmResult<String> {
        self.context.with_pkcs11(|pkcs11| {
            let info = pkcs11.get_slot_info(self.slot)?;
            Ok(format!(
                "Slot: {} ({})",
                info.slot_description(),
                if info.token_present() {
                    "token present"
                } else {
                    "no token"
                }
            ))
        })
    }

    /// Get token information description.
    pub fn token_info(&self) -> HsmResult<String> {
        self.context.with_pkcs11(|pkcs11| {
            let info = pkcs11.get_token_info(self.slot)?;
            Ok(format!("Token: {}", info.label()))
        })
    }

    /// Get token label.
    pub fn token_label(&self) -> HsmResult<String> {
        self.context.with_pkcs11(|pkcs11| {
            let info = pkcs11.get_token_info(self.slot)?;
            Ok(info.label().trim().to_string())
        })
    }

    /// Open a read-only session.
    pub fn open_ro_session(&self) -> HsmResult<Session> {
        self.context.with_pkcs11(|pkcs11| {
            pkcs11
                .open_ro_session(self.slot)
                .map_err(|e| HsmError::SessionCreate(format!("Failed to open RO session: {e}")))
        })
    }

    /// Open a read-write session.
    pub fn open_rw_session(&self) -> HsmResult<Session> {
        self.context.with_pkcs11(|pkcs11| {
            pkcs11
                .open_rw_session(self.slot)
                .map_err(|e| HsmError::SessionCreate(format!("Failed to open RW session: {e}")))
        })
    }

    /// Login to the slot as a user.
    ///
    /// # Arguments
    ///
    /// * `session` - Active session
    /// * `pin` - User PIN
    pub fn login(&self, session: &Session, pin: &str) -> HsmResult<()> {
        session
            .login(UserType::User, Some(&AuthPin::new(pin.to_owned().into())))
            .map_err(|e| HsmError::Login(format!("User login failed: {e}")))
    }

    /// Login as security officer (SO).
    ///
    /// # Arguments
    ///
    /// * `session` - Active session
    /// * `pin` - SO PIN
    pub fn login_so(&self, session: &Session, pin: &str) -> HsmResult<()> {
        session
            .login(UserType::So, Some(&AuthPin::new(pin.to_owned().into())))
            .map_err(|e| HsmError::Login(format!("SO login failed: {e}")))
    }

    /// Enumerate all slots with tokens present.
    ///
    /// # Arguments
    ///
    /// * `context` - PKCS#11 library context
    pub fn enumerate_slots_with_tokens(context: &Pkcs11Context) -> HsmResult<Vec<Slot>> {
        context.with_pkcs11(|pkcs11| {
            pkcs11
                .get_slots_with_token()
                .map_err(|e| HsmError::SlotAccess(format!("Failed to enumerate slots: {e}")))
        })
    }

    /// Find the first slot with a token.
    ///
    /// # Arguments
    ///
    /// * `context` - PKCS#11 library context
    pub fn find_first_slot(context: &Pkcs11Context) -> HsmResult<Self> {
        let slots = Self::enumerate_slots_with_tokens(context)?;

        let slot = slots
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::SlotAccess("No slots with tokens found".to_string()))?;

        Ok(Self::new(context.clone(), slot))
    }

    /// Find a slot by token label.
    ///
    /// # Arguments
    ///
    /// * `context` - PKCS#11 library context
    /// * `label` - Token label to search for
    pub fn find_by_label(context: &Pkcs11Context, label: &str) -> HsmResult<Self> {
        let slots = Self::enumerate_slots_with_tokens(context)?;

        for slot_id in slots {
            let slot = Self::new(context.clone(), slot_id);
            if let Ok(token_label) = slot.token_label()
                && token_label == label
            {
                return Ok(slot);
            }
        }

        Err(HsmError::SlotAccess(format!(
            "No slot found with token label '{label}'"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires HSM hardware"]
    fn test_slot_enumeration() {
        // Would require a real PKCS#11 setup
    }
}
