// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT
pub mod tpm_utiles;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Server {
    pub url: String,
    pub cert: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub servers: Vec<Server>,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Key {
    pub key_type: String,
    pub key: String,
}
