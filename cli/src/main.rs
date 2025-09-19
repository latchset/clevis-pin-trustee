// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use clap::{Parser, Subcommand};
use clevis_pin_trustee_lib::*;
use josekit::jwe::alg::direct::DirectJweAlgorithm::Dir;
use josekit::jwk::Jwk;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::process::Command as StdCommand;
use std::thread;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
struct ClevisHeader {
    pin: String,
    servers: Vec<Server>,
    path: String,
}

fn fetch_and_prepare_jwk(servers: &[Server], path: &str) -> Result<Jwk> {
    let key = fetch_luks_key(servers, path)?;
    let key = String::from_utf8(
        general_purpose::STANDARD
            .decode(&key)
            .context("Error decoding key in base64")?,
    )
    .context("Error decoding the key in JSON")?;
    eprintln!("Key: {:?}", key);
    let key: Key = serde_json::from_str(&key).context("Error in parsing the fetched key")?;

    let mut jwk = Jwk::new(&key.key_type);
    jwk.set_key_value(&key.key);
    jwk.set_key_operations(vec!["encrypt", "decrypt"]);

    Ok(jwk)
}

fn encrypt(config: &str) -> Result<()> {
    let config: Config =
        serde_json::from_str(config).map_err(|e| anyhow!("Failed to parse config JSON: {}", e))?;

    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    let jwk = fetch_and_prepare_jwk(&config.servers, &config.path)?;

    eprintln!("{}", jwk);
    let encrypter = Dir
        .encrypter_from_jwk(&jwk)
        .context("Error creating direct encrypter")?;

    let private_hdr = ClevisHeader {
        pin: "trustee".to_string(),
        servers: config.servers.clone(),
        path: config.path,
    };

    let mut hdr = josekit::jwe::JweHeader::new();
    hdr.set_algorithm("ECDH-ES");
    hdr.set_content_encryption("A256GCM");
    hdr.set_claim(
        "clevis",
        Some(serde_json::value::to_value(private_hdr).context("Error serializing private header")?),
    )
    .context("Error adding clevis claim")?;

    let jwe_token = josekit::jwe::serialize_compact(&input, &hdr, &encrypter)
        .context("Error serializing JWE token")?;

    io::stdout()
        .write_all(jwe_token.as_bytes())
        .context("Error writing the token on stdout")?;
    eprintln!("Encryption successful.");

    Ok(())
}

fn decrypt() -> Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let input = std::str::from_utf8(&input).context("Input is not valid UTF-8")?;

    let hdr = josekit::jwt::decode_header(input).context("Error decoding header")?;
    let hdr_clevis = hdr.claim("clevis").context("Error getting clevis claim")?;
    let hdr_clevis: ClevisHeader =
        serde_json::from_value(hdr_clevis.clone()).context("Error deserializing clevis header")?;

    eprintln!("Decrypt with header: {:?}", hdr_clevis);

    let decrypter_jwk = fetch_and_prepare_jwk(&hdr_clevis.servers, &hdr_clevis.path)?;

    let decrypter = Dir
        .decrypter_from_jwk(&decrypter_jwk)
        .context("Error creating decrypter")?;

    let (payload, _) =
        josekit::jwe::deserialize_compact(input, &decrypter).context("Error decrypting JWE")?;

    io::stdout().write_all(&payload)?;

    eprintln!("Decryption successful.");
    Ok(())
}

fn fetch_luks_key(servers: &[Server], path: &str) -> Result<String> {
    const MAX_ATTEMPTS: u32 = 3;
    const DELAY: Duration = Duration::from_secs(5);

    if servers.is_empty() {
        return Err(anyhow!("No URLs provided"));
    }

    (1..=MAX_ATTEMPTS)
        .find_map(|attempt| {
            eprintln!(
                "Attempting to fetch LUKS key (attempt {}/{})",
                attempt, MAX_ATTEMPTS
            );

            for (index, server) in servers.iter().enumerate() {
                eprintln!("Trying URL {}/{}: {}", index + 1, servers.len(), server.url);
                match try_fetch_luks_key(&server.url, path) {
                    Ok(key) => {
                        eprintln!("Successfully fetched LUKS key from URL: {}", server.url);
                        return Some(Ok(key));
                    }
                    Err(e) => {
                        eprintln!("Error with URL {}: {}", server.url, e);
                    }
                }
            }

            if attempt < MAX_ATTEMPTS {
                eprintln!(
                    "All URLs failed for attempt {}. Retrying in {:?} seconds...",
                    attempt, DELAY
                );
                thread::sleep(DELAY);
            }
            None
        })
        .unwrap_or_else(|| {
            Err(anyhow!(
                "Failed to fetch the LUKS key from all URLs after {} attempts",
                MAX_ATTEMPTS
            ))
        })
}

fn try_fetch_luks_key(url: &str, path: &str) -> Result<String> {
    let output = StdCommand::new("trustee-attester")
        .arg("--url")
        .arg(url)
        .arg("get-resource")
        .arg("--path")
        .arg(path)
        .output()
        .map_err(|e| anyhow!("Failed to execute trustee-attester: {}", e))?;

    io::stderr().write_all(&output.stderr)?;
    io::stderr().write_all(&output.stdout)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("trustee-attester failed: {}", stderr));
    }

    let key = String::from_utf8(output.stdout)
        .map_err(|e| anyhow!("Invalid UTF-8 for the LUKS key: {}", e))?
        .trim()
        .to_string();

    if key.is_empty() {
        return Err(anyhow!("Received empty LUKS key"));
    }

    Ok(key)
}

/// Clevis PIN for confidential cluster
#[derive(Parser)]
#[command(name = "clevis-pin-trustee")]
#[command(version = "0.1.0")]
#[command(about = "Clevis PIN for confidential clusters")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt data using the configuration
    Encrypt {
        /// Input data or arguments
        config: String,
    },
    /// Decrypt the input data
    Decrypt,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { config } => encrypt(&config),
        Commands::Decrypt => decrypt(),
    }
}
