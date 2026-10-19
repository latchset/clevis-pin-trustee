// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum NumRetries {
    Finite(u32),
    Infinity,
}

impl Serialize for NumRetries {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            NumRetries::Finite(n) => serializer.serialize_u32(*n),
            NumRetries::Infinity => serializer.serialize_str("infinity"),
        }
    }
}

impl<'de> Deserialize<'de> for NumRetries {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NumRetriesVisitor;

        impl<'de> serde::de::Visitor<'de> for NumRetriesVisitor {
            type Value = NumRetries;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a positive number (>= 1) or the string 'infinity'")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value == 0 {
                    return Err(E::custom("number must be at least 1, got: 0"));
                }
                if value > u32::MAX as u64 {
                    return Err(E::custom(format!("number too large: {}", value)));
                }
                Ok(NumRetries::Finite(value as u32))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value <= 0 {
                    return Err(E::custom(format!(
                        "number must be at least 1, got: {}",
                        value
                    )));
                }
                if value > u32::MAX as i64 {
                    return Err(E::custom(format!("number too large: {}", value)));
                }
                Ok(NumRetries::Finite(value as u32))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value == "infinity" {
                    Ok(NumRetries::Infinity)
                } else {
                    Err(E::custom(format!("expected 'infinity', got: '{}'", value)))
                }
            }
        }

        deserializer.deserialize_any(NumRetriesVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Server {
    pub url: String,
    pub cert: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationKey {
    pub registration: Registration,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Registration {
    pub url: String,
    pub cert: String,
    pub uuid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub servers: Vec<Server>,
    pub path: String,
    pub initdata: Option<String>,
    pub num_retries: Option<NumRetries>,
    pub attestation_key: Option<AttestationKey>,
    #[serde(default)]
    pub offline: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Key {
    pub key_type: String,
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
/// Sync with Trustee attestation_service::Initdata
pub struct Initdata {
    pub version: String,
    pub algorithm: String,
    pub data: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationPayload {
    pub attestation_key: String,
    pub uuid: String,
}
