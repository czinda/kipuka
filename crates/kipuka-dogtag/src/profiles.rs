//! Enrollment profile operations via Dogtag CA REST API.
//!
//! Provides profile enumeration and constraint extraction from
//! `/ca/rest/profiles`. Profile constraints are used by kipuka's
//! `/csrattrs` endpoint to derive CSR attribute hints per RFC 7030 S4.5.

use serde::Deserialize;
use tracing::debug;

use crate::client::DogtagClient;
use crate::DogtagResult;

/// Summary information about an enrollment profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProfileInfo {
    /// Profile identifier (e.g., "caServerCert").
    pub profile_id: String,
    /// Human-readable profile name.
    #[serde(default)]
    pub name: Option<String>,
    /// Profile description.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether the profile is enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Whether the profile is visible to end entities.
    #[serde(default)]
    pub visible: Option<bool>,
}

/// Detailed profile definition including inputs, outputs, and policy sets.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProfileDetail {
    /// Profile identifier.
    pub profile_id: String,
    /// Human-readable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Profile description.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether the profile is enabled.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Policy set constraints defining the certificate structure.
    #[serde(default)]
    pub policy_sets: Vec<PolicySet>,
}

/// A named group of policies within a profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicySet {
    /// Policy set identifier.
    #[serde(default)]
    pub id: Option<String>,
    /// Individual policies in this set.
    #[serde(default)]
    pub policies: Vec<Policy>,
}

/// A single profile policy (constraint or default).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Policy {
    /// Policy identifier.
    #[serde(default)]
    pub id: Option<String>,
    /// Constraint definition.
    #[serde(default)]
    pub constraint: Option<Constraint>,
    /// Default values.
    #[serde(default)]
    pub defaults: Vec<PolicyDefault>,
}

/// A constraint within a profile policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Constraint {
    /// Constraint class (e.g., "keyConstraintImpl").
    #[serde(default)]
    pub class_id: Option<String>,
    /// Constraint parameters.
    #[serde(default)]
    pub params: Vec<ConstraintParam>,
}

/// A single constraint parameter (name-value pair).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConstraintParam {
    /// Parameter name (e.g., "keyType", "keyParameters").
    pub name: String,
    /// Parameter value.
    #[serde(default)]
    pub value: Option<String>,
}

/// Default value within a policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyDefault {
    /// Default class (e.g., "keyUsageExtDefaultImpl").
    #[serde(default)]
    pub class_id: Option<String>,
    /// Default parameters.
    #[serde(default)]
    pub params: Vec<ConstraintParam>,
}

/// Extracted constraints from a profile, suitable for deriving CSR attributes.
///
/// Used by kipuka's `/csrattrs` endpoint to tell EST clients what to
/// include in their certificate signing requests.
#[derive(Debug, Clone, Default)]
pub struct ProfileConstraints {
    /// Allowed key types (e.g., "RSA", "EC", "ML-DSA").
    pub key_types: Vec<String>,
    /// Allowed key sizes or named curves (e.g., "2048", "P-256", "ML-DSA-65").
    pub key_parameters: Vec<String>,
    /// Key usage flags (e.g., "digitalSignature", "keyEncipherment").
    pub key_usage: Vec<String>,
    /// Extended key usage OIDs (e.g., "1.3.6.1.5.5.7.3.1" for TLS server).
    pub extended_key_usage: Vec<String>,
    /// Required subject DN components (e.g., "CN", "O", "OU").
    pub subject_dn_components: Vec<String>,
}

/// Response from profile listing.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProfileListResponse {
    #[serde(default)]
    entries: Vec<ProfileInfo>,
}

impl DogtagClient {
    /// List all enrollment profiles.
    ///
    /// Sends `GET /ca/rest/profiles` and returns summary information
    /// for each profile. Only enabled and visible profiles are typically
    /// relevant for EST enrollment.
    pub async fn list_profiles(&self) -> DogtagResult<Vec<ProfileInfo>> {
        debug!("Listing enrollment profiles");
        let resp = self.get("/ca/rest/profiles").await?;
        let list: ProfileListResponse = Self::json_response(resp).await?;
        Ok(list.entries)
    }

    /// Get detailed profile definition by ID.
    ///
    /// Sends `GET /ca/rest/profiles/{id}` and returns the full profile
    /// definition including policy sets, constraints, and defaults.
    pub async fn get_profile(&self, id: &str) -> DogtagResult<ProfileDetail> {
        debug!(profile = id, "Fetching profile detail");
        let resp = self.get(&format!("/ca/rest/profiles/{id}")).await?;
        Self::json_response(resp).await
    }

    /// Extract CSR-relevant constraints from a profile.
    ///
    /// Parses the profile's policy sets to extract key type constraints,
    /// key usage extensions, and subject DN requirements. The returned
    /// [`ProfileConstraints`] can be translated into EST CSR attributes
    /// for the `/csrattrs` endpoint.
    pub async fn get_profile_constraints(
        &self,
        id: &str,
    ) -> DogtagResult<ProfileConstraints> {
        let detail = self.get_profile(id).await?;
        Ok(extract_constraints(&detail))
    }
}

/// Parse profile policy sets to extract enrollment constraints.
fn extract_constraints(profile: &ProfileDetail) -> ProfileConstraints {
    let mut constraints = ProfileConstraints::default();

    for policy_set in &profile.policy_sets {
        for policy in &policy_set.policies {
            // Extract key constraints.
            if let Some(ref constraint) = policy.constraint {
                if constraint.class_id.as_deref() == Some("keyConstraintImpl") {
                    for param in &constraint.params {
                        match param.name.as_str() {
                            "keyType" => {
                                if let Some(ref v) = param.value {
                                    constraints.key_types.push(v.clone());
                                }
                            }
                            "keyParameters" => {
                                if let Some(ref v) = param.value {
                                    for p in v.split(',') {
                                        constraints.key_parameters.push(p.trim().to_owned());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Extract defaults (key usage, EKU, subject DN).
            for default in &policy.defaults {
                match default.class_id.as_deref() {
                    Some("keyUsageExtDefaultImpl") => {
                        for param in &default.params {
                            if param.value.as_deref() == Some("true") {
                                constraints.key_usage.push(param.name.clone());
                            }
                        }
                    }
                    Some("extendedKeyUsageExtDefaultImpl") => {
                        for param in &default.params {
                            if let Some(ref v) = param.value {
                                constraints.extended_key_usage.push(v.clone());
                            }
                        }
                    }
                    Some("subjectNameDefaultImpl") | Some("nsSubjectNameDefaultImpl") => {
                        for param in &default.params {
                            if param.name == "name" {
                                if let Some(ref v) = param.value {
                                    // Extract DN component names (CN, O, OU, etc.).
                                    for component in v.split(',') {
                                        if let Some(name) = component.split('=').next() {
                                            let name = name.trim();
                                            if !name.is_empty()
                                                && !constraints
                                                    .subject_dn_components
                                                    .contains(&name.to_owned())
                                            {
                                                constraints
                                                    .subject_dn_components
                                                    .push(name.to_owned());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    constraints
}
