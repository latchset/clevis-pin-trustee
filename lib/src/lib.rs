// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Server {
    pub url: String,
    pub cert: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub servers: Vec<Server>,
    pub path: String,
    pub initdata: Option<String>,
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
