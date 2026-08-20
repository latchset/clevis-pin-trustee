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
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::Command as StdCommand;
use std::time::Duration;
use std::{fs, thread};

const DEFAULT_TRIES: u32 = 10;
const DELAY: Duration = Duration::from_secs(5);

// TPM constants
const TPM_DIR: &str = "/var/tpm";
const AK_PATH: &str = "/var/tpm/ak.pub";
const AK_CTX_PATH: &str = "/var/tpm/ak.ctx";
const AK_REGISTERD: &str = "/var/tpm/ak.registerd";
const AK_HANDLE: &str = "0x81010002";
const EK_HANDLE: &str = "0x81010001";

/// Trait for executing commands to fetch LUKS keys
trait CommandExecutor {
    fn try_fetch_luks_key(
        &self,
        url: &str,
        path: &str,
        cert: &str,
        initdata: Option<String>,
    ) -> Result<String>;
}

/// Trait for generating attestation keys
trait AttestationKeyGeneratorTrait {
    fn generate_attestation_key(&self) -> Result<String>;
}

/// Response wrapper to make HTTP responses mockable
struct HttpResponse {
    status_code: u16,
}

impl HttpResponse {
    fn is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }

    fn status_code(&self) -> u16 {
        self.status_code
    }
}

/// Trait for HTTP client operations
trait HttpClient {
    fn put_json(&self, url: &str, payload: &RegistrationPayload) -> Result<HttpResponse>;
}

/// Trait for filesystem operations
trait FileSystem {
    fn write_marker(&self, path: &str) -> Result<()>;
}

/// Real implementation that calls the trustee-attester binary
struct RealCommandExecutor;

impl CommandExecutor for RealCommandExecutor {
    fn try_fetch_luks_key(
        &self,
        url: &str,
        path: &str,
        cert: &str,
        initdata: Option<String>,
    ) -> Result<String> {
        let mut command = StdCommand::new("trustee-attester");
        if !cert.is_empty() {
            // Create a unique filename based on the URL
            let url_sanitized = url.replace("://", "_").replace("/", "_").replace(":", "_");
            let cert_path = format!("/run/trustee/cert_{}.pem", url_sanitized);
            let cert_path_obj = Path::new(&cert_path);
            if let Some(parent) = cert_path_obj.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&cert_path, cert)?;
            command.arg("--cert-file").arg(&cert_path);
        }
        command
            .arg("--url")
            .arg(url)
            .arg("get-resource")
            .arg("--path")
            .arg(path);
        if let Some(initdata_str) = initdata {
            command.arg("--initdata").arg(initdata_str);
        }
        let output = command
            .output()
            .map_err(|e| anyhow!("Failed to execute trustee-attester: {}", e))?;

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
}

/// Real implementation that generates attestation keys using TPM
struct AttestationKeyGenerator;

impl AttestationKeyGeneratorTrait for AttestationKeyGenerator {
    fn generate_attestation_key(&self) -> Result<String> {
        generate_attestation_key()
    }
}

/// Real HTTP client wrapper
struct RealHttpClient {
    client: reqwest::blocking::Client,
}

impl HttpClient for RealHttpClient {
    fn put_json(&self, url: &str, payload: &RegistrationPayload) -> Result<HttpResponse> {
        let response = self
            .client
            .put(url)
            .json(payload)
            .send()
            .map_err(|e| anyhow!("Failed to send PUT request: {}", e))?;

        Ok(HttpResponse {
            status_code: response.status().as_u16(),
        })
    }
}

/// Real filesystem implementation
struct RealFileSystem;

impl FileSystem for RealFileSystem {
    fn write_marker(&self, path: &str) -> Result<()> {
        fs::write(path, "").context("Failed to write marker file")
    }
}

#[cfg(test)]
pub struct MockCommandExecutor {
    pub response: Result<String>,
}

#[cfg(test)]
impl CommandExecutor for MockCommandExecutor {
    fn try_fetch_luks_key(
        &self,
        _url: &str,
        _path: &str,
        _cert: &str,
        _initdata: Option<String>,
    ) -> Result<String> {
        match &self.response {
            Ok(key) => Ok(key.clone()),
            Err(e) => Err(anyhow!("{}", e)),
        }
    }
}

#[cfg(test)]
pub struct MockAttestationKeyGenerator {
    pub response: Result<String>,
}

#[cfg(test)]
impl AttestationKeyGeneratorTrait for MockAttestationKeyGenerator {
    fn generate_attestation_key(&self) -> Result<String> {
        match &self.response {
            Ok(key) => Ok(key.clone()),
            Err(e) => Err(anyhow!("{}", e)),
        }
    }
}

#[cfg(test)]
pub struct MockHttpClient {
    pub responses: Vec<Result<u16>>,
    pub call_count: std::cell::RefCell<usize>,
}

#[cfg(test)]
impl HttpClient for MockHttpClient {
    fn put_json(&self, _url: &str, _payload: &RegistrationPayload) -> Result<HttpResponse> {
        let mut count = self.call_count.borrow_mut();
        let index = *count;
        *count += 1;

        if index >= self.responses.len() {
            return Err(anyhow!("No more mock responses available"));
        }

        match &self.responses[index] {
            Ok(status_code) => Ok(HttpResponse {
                status_code: *status_code,
            }),
            Err(e) => Err(anyhow!("{}", e)),
        }
    }
}

#[cfg(test)]
pub struct MockFileSystem {
    pub write_result: Result<()>,
    pub written: std::cell::RefCell<Vec<String>>,
}

#[cfg(test)]
impl FileSystem for MockFileSystem {
    fn write_marker(&self, path: &str) -> Result<()> {
        self.written.borrow_mut().push(path.to_string());
        match &self.write_result {
            Ok(()) => Ok(()),
            Err(e) => Err(anyhow!("{}", e)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ClevisHeader {
    pin: String,
    servers: Vec<Server>,
    path: String,
    initdata: Option<String>,
    #[serde(default)]
    num_retries: Option<NumRetries>,
}

fn fetch_and_prepare_jwk<E: CommandExecutor>(
    servers: &[Server],
    path: &str,
    initdata: Option<String>,
    num_retries: &NumRetries,
    executor: &E,
) -> Result<Jwk> {
    let key = fetch_luks_key(servers, path, initdata, num_retries, executor)?;
    let key = String::from_utf8(
        general_purpose::STANDARD
            .decode(&key)
            .map_err(|_| anyhow!("Error decoding key in base64"))?,
    )
    .context("Error decoding the key in JSON")?;
    // Hide key contents, do not print context
    let key: Key =
        serde_json::from_str(&key).map_err(|_| anyhow!("Error in parsing the fetched key"))?;

    let mut jwk = Jwk::new(&key.key_type);
    jwk.set_key_value(&key.key);
    jwk.set_key_operations(vec!["encrypt", "decrypt"]);

    Ok(jwk)
}

fn generate_attestation_key() -> Result<String> {
    fs::create_dir_all(TPM_DIR)
        .with_context(|| format!("couldn't create {} directory", TPM_DIR))?;

    if Path::new(AK_PATH).exists() {
        eprintln!("Attestation Key already exists, skipping generation");
        return fs::read_to_string(AK_PATH).context("Failed to read existing attestation key");
    }

    eprintln!("Generating Attestation Key");

    // Generate attestation key using tpm2_createak
    let output = StdCommand::new("tpm2_createak")
        .args([
            "-C",
            EK_HANDLE,
            "-c",
            AK_CTX_PATH,
            "-G",
            "rsa",
            "-g",
            "sha256",
            "-s",
            "rsassa",
            "-u",
            AK_PATH,
            "-f",
            "pem",
        ])
        .output()
        .context("Failed to execute tpm2_createak command")?;

    io::stderr().write_all(&output.stderr)?;
    io::stderr().write_all(&output.stdout)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("failed to create attestation key: {}", stderr));
    }

    eprintln!("Persisting Attestation Key");

    // Persist attestation key using tpm2_evictcontrol
    let output = StdCommand::new("tpm2_evictcontrol")
        .args(["-c", AK_CTX_PATH, AK_HANDLE])
        .output()
        .context("Failed to execute tpm2_evictcontrol command")?;

    io::stderr().write_all(&output.stderr)?;
    io::stderr().write_all(&output.stdout)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("failed to persist attestation key: {}", stderr));
    }

    // Read and return the generated attestation key
    fs::read_to_string(AK_PATH).context("Failed to read generated attestation key")
}

fn attestation_key_handle_with_deps<G, C, F>(
    attestation_key: &Option<AttestationKey>,
    generator: &G,
    http_client_factory: C,
    filesystem: &F,
) -> Result<()>
where
    G: AttestationKeyGeneratorTrait,
    C: Fn(&str) -> Result<Box<dyn HttpClient>>,
    F: FileSystem,
{
    if attestation_key.is_none() {
        return Ok(());
    }

    let key_config = attestation_key.as_ref().unwrap();
    let generated_key = generator.generate_attestation_key()?;

    if !key_config.registration.url.is_empty() {
        let payload = RegistrationPayload {
            attestation_key: generated_key,
            uuid: key_config.registration.uuid.clone(),
        };

        let client = http_client_factory(&key_config.registration.cert)?;

        let mut last_error = None;
        for attempt in 1..=DEFAULT_TRIES {
            eprintln!(
                "Attempting to register attestation key (attempt {}/{})",
                attempt, DEFAULT_TRIES
            );

            match client.put_json(&key_config.registration.url, &payload) {
                Ok(response) => {
                    if response.is_success() {
                        eprintln!("Attestation key registered successfully.");

                        // Create the registered marker file
                        filesystem.write_marker(AK_REGISTERD)?;

                        return Ok(());
                    } else {
                        last_error = Some(anyhow!(
                            "Attestation key registration failed with status: {}",
                            response.status_code()
                        ));
                        eprintln!(
                            "Registration attempt {} failed with status: {}",
                            attempt,
                            response.status_code()
                        );
                    }
                }
                Err(e) => {
                    last_error = Some(anyhow!(
                        "Failed to send PUT request for attestation key registration: {}",
                        e
                    ));
                    eprintln!("Registration attempt {} failed: {}", attempt, e);
                }
            }

            if attempt < DEFAULT_TRIES {
                eprintln!("Retrying in {:?}...", DELAY);
                thread::sleep(DELAY);
            }
        }

        return Err(last_error.unwrap_or_else(|| {
            anyhow!(
                "Failed to register attestation key after {} attempts",
                DEFAULT_TRIES
            )
        }));
    }

    Ok(())
}

fn attestation_key_handle(attestation_key: &Option<AttestationKey>) -> Result<()> {
    let generator = AttestationKeyGenerator;
    let filesystem = RealFileSystem;
    let http_client_factory = |cert: &str| -> Result<Box<dyn HttpClient>> {
        let client = if cert.is_empty() {
            reqwest::blocking::Client::new()
        } else {
            let cert = reqwest::Certificate::from_pem(cert.as_bytes())
                .context("Failed to parse TLS certificate")?;
            reqwest::blocking::Client::builder()
                .add_root_certificate(cert)
                .build()
                .context("Failed to build HTTPS client")?
        };
        Ok(Box::new(RealHttpClient { client }))
    };

    attestation_key_handle_with_deps(
        attestation_key,
        &generator,
        http_client_factory,
        &filesystem,
    )
}

fn encrypt(config: &str) -> Result<()> {
    let config: Config =
        serde_json::from_str(config).map_err(|e| anyhow!("Failed to parse config JSON: {}", e))?;

    attestation_key_handle(&config.attestation_key)?;

    let initdata_str = config.initdata.as_ref();
    let initdata_data: Option<HashMap<String, String>> = initdata_str
        .map(|s| {
            serde_json::from_str(s).map_err(|e| anyhow!("Failed to parse config initdata: {e}"))
        })
        .transpose()?;
    let initdata = initdata_data
        .map(|data| {
            toml::to_string(&Initdata {
                version: "0.1.0".to_string(),
                algorithm: "sha256".to_string(),
                data,
            })
            .map_err(|e| anyhow!("Failed to serialize initdata: {e}"))
        })
        .transpose()?;

    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    let executor = RealCommandExecutor;
    let num_retries = config
        .num_retries
        .as_ref()
        .unwrap_or(&NumRetries::Finite(DEFAULT_TRIES));
    let jwk = fetch_and_prepare_jwk(
        &config.servers,
        &config.path,
        initdata.clone(),
        num_retries,
        &executor,
    )?;

    eprintln!("{}", jwk);
    let encrypter = Dir
        .encrypter_from_jwk(&jwk)
        .context("Error creating direct encrypter")?;

    let private_hdr = ClevisHeader {
        pin: "trustee".to_string(),
        servers: config.servers.clone(),
        path: config.path,
        initdata,
        num_retries: config.num_retries,
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

    let executor = RealCommandExecutor;
    let num_retries = hdr_clevis
        .num_retries
        .as_ref()
        .unwrap_or(&NumRetries::Finite(DEFAULT_TRIES));
    let decrypter_jwk = fetch_and_prepare_jwk(
        &hdr_clevis.servers,
        &hdr_clevis.path,
        hdr_clevis.initdata,
        num_retries,
        &executor,
    )?;

    let decrypter = Dir
        .decrypter_from_jwk(&decrypter_jwk)
        .context("Error creating decrypter")?;

    let (payload, _) =
        josekit::jwe::deserialize_compact(input, &decrypter).context("Error decrypting JWE")?;

    io::stdout().write_all(&payload)?;

    eprintln!("Decryption successful.");
    Ok(())
}

fn try_fetch_from_servers<E: CommandExecutor>(
    servers: &[Server],
    path: &str,
    initdata: &Option<String>,
    executor: &E,
) -> Result<String> {
    let mut err = String::new();
    for (index, server) in servers.iter().enumerate() {
        eprintln!("Trying URL {}/{}: {}", index + 1, servers.len(), server.url);
        match executor.try_fetch_luks_key(&server.url, path, &server.cert, initdata.clone()) {
            Ok(key) => {
                eprintln!("Successfully fetched LUKS key from URL: {}", server.url);
                return Ok(key);
            }
            Err(e) => {
                err.push_str(&format!("\nError with URL {}: {e}", server.url));
            }
        }
    }
    Err(anyhow!("{err}"))
}

fn fetch_luks_key<E: CommandExecutor>(
    servers: &[Server],
    path: &str,
    initdata: Option<String>,
    num_retries: &NumRetries,
    executor: &E,
) -> Result<String> {
    if servers.is_empty() {
        return Err(anyhow!("No URLs provided"));
    }

    let mut last_err = anyhow!("");
    match num_retries {
        NumRetries::Finite(max_attempts) => (1..=*max_attempts)
            .find_map(|attempt| {
                eprintln!(
                    "Attempting to fetch LUKS key (attempt {}/{})",
                    attempt, max_attempts
                );

                match try_fetch_from_servers(servers, path, &initdata, executor) {
                    Ok(key) => return Some(Ok(key)),
                    Err(e) => last_err = e,
                }

                if attempt < *max_attempts {
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
                    "Failed to fetch the LUKS key from all URLs after {max_attempts} attempts, last errors were:{last_err}",
                ))
            }),
        NumRetries::Infinity => {
            let mut attempt = 0;
            loop {
                attempt += 1;
                eprintln!("Attempting to fetch LUKS key (attempt {})", attempt);

                let result = try_fetch_from_servers(servers, path, &initdata, executor);
                if result.is_ok() {
                    return result;
                }
                eprintln!(
                    "All URLs failed for attempt {attempt} with errors {}. Retrying in {:?} seconds...",
                    result.unwrap_err(),
                    DELAY
                );
                thread::sleep(DELAY);
            }
        }
    }
}

/// Clevis PIN for Trustee
#[derive(Parser)]
#[command(name = "clevis-pin-trustee")]
#[command(version = "0.1.0")]
#[command(about = "Clevis PIN for Trustee")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_luks_key_success() {
        let mock = MockCommandExecutor {
            response: Ok("test_luks_key_12345".to_string()),
        };

        let servers = vec![Server {
            url: "http://server1.example.com".to_string(),
            cert: String::new(),
        }];

        let num_retries = NumRetries::Finite(3);
        let result = fetch_luks_key(&servers, "/test/path", None, &num_retries, &mock);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_luks_key_12345");
    }

    #[test]
    fn test_fetch_luks_key_error() {
        let mock = MockCommandExecutor {
            response: Err(anyhow!("Failed to connect to server")),
        };

        let servers = vec![Server {
            url: "http://server1.example.com".to_string(),
            cert: String::new(),
        }];

        let num_retries = NumRetries::Finite(3);
        let result = fetch_luks_key(&servers, "/test/path", None, &num_retries, &mock);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to fetch the LUKS key from all URLs after 3 attempts, last errors were:\nError with URL http://server1.example.com: Failed to connect to server"
        );
    }

    #[test]
    fn test_fetch_luks_key_infinity_retries() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::Instant;

        let mock = MockCommandExecutor {
            response: Err(anyhow!("Failed to connect to server")),
        };

        let servers = vec![Server {
            url: "http://server1.example.com".to_string(),
            cert: String::new(),
        }];

        let num_retries = NumRetries::Infinity;

        let returned = Arc::new(AtomicBool::new(false));
        let returned_clone = Arc::clone(&returned);
        let handle = std::thread::spawn(move || {
            let _ = fetch_luks_key(&servers, "/test/path", None, &num_retries, &mock);
            returned_clone.store(true, Ordering::SeqCst);
        });
        let start = Instant::now();
        let timeout = Duration::from_secs(60);

        while start.elapsed() < timeout {
            thread::sleep(Duration::from_secs(1));
            if returned.load(Ordering::SeqCst) {
                panic!("fetch_luks_key returned before 1 minute with infinite retries");
            }
        }

        assert!(
            !returned.load(Ordering::SeqCst),
            "fetch_luks_key should not have returned after 1 minute with infinite retries"
        );

        drop(handle);
    }

    #[test]
    fn test_attestation_key_handle_none() {
        let generator = MockAttestationKeyGenerator {
            response: Ok("mock_key".to_string()),
        };
        let filesystem = MockFileSystem {
            write_result: Ok(()),
            written: std::cell::RefCell::new(Vec::new()),
        };
        let http_client_factory = |_cert: &str| -> Result<Box<dyn HttpClient>> {
            panic!("HTTP client should not be called when attestation_key is None");
        };

        let result =
            attestation_key_handle_with_deps(&None, &generator, http_client_factory, &filesystem);

        assert!(result.is_ok());
        assert!(filesystem.written.borrow().is_empty());
    }

    #[test]
    fn test_attestation_key_handle_empty_registration_url() {
        let generator = MockAttestationKeyGenerator {
            response: Ok("mock_attestation_key".to_string()),
        };
        let filesystem = MockFileSystem {
            write_result: Ok(()),
            written: std::cell::RefCell::new(Vec::new()),
        };
        let http_client_factory = |_cert: &str| -> Result<Box<dyn HttpClient>> {
            panic!("HTTP client should not be called when registration URL is empty");
        };

        let attestation_key = Some(AttestationKey {
            registration: Registration {
                url: String::new(),
                cert: String::new(),
                uuid: "test-uuid".to_string(),
            },
        });

        let result = attestation_key_handle_with_deps(
            &attestation_key,
            &generator,
            http_client_factory,
            &filesystem,
        );

        assert!(result.is_ok());
        assert!(filesystem.written.borrow().is_empty());
    }

    #[test]
    fn test_attestation_key_handle_successful_registration() {
        let generator = MockAttestationKeyGenerator {
            response: Ok("mock_attestation_key".to_string()),
        };
        let filesystem = MockFileSystem {
            write_result: Ok(()),
            written: std::cell::RefCell::new(Vec::new()),
        };
        let http_client_factory = move |_cert: &str| -> Result<Box<dyn HttpClient>> {
            Ok(Box::new(MockHttpClient {
                responses: vec![Ok(200)],
                call_count: std::cell::RefCell::new(0),
            }))
        };

        let attestation_key = Some(AttestationKey {
            registration: Registration {
                url: "http://test.example.com/register".to_string(),
                cert: String::new(),
                uuid: "test-uuid-123".to_string(),
            },
        });

        let result = attestation_key_handle_with_deps(
            &attestation_key,
            &generator,
            http_client_factory,
            &filesystem,
        );

        assert!(result.is_ok());
        assert_eq!(filesystem.written.borrow().len(), 1);
        assert_eq!(filesystem.written.borrow()[0], AK_REGISTERD);
    }

    #[test]
    fn test_attestation_key_handle_registration_fails_with_retries() {
        let generator = MockAttestationKeyGenerator {
            response: Ok("mock_attestation_key".to_string()),
        };
        let filesystem = MockFileSystem {
            write_result: Ok(()),
            written: std::cell::RefCell::new(Vec::new()),
        };
        let http_client_factory = move |_cert: &str| -> Result<Box<dyn HttpClient>> {
            Ok(Box::new(MockHttpClient {
                responses: vec![
                    Ok(500),
                    Ok(500),
                    Ok(500),
                    Ok(500),
                    Ok(500),
                    Ok(500),
                    Ok(500),
                    Ok(500),
                    Ok(500),
                    Ok(500),
                ],
                call_count: std::cell::RefCell::new(0),
            }))
        };

        let attestation_key = Some(AttestationKey {
            registration: Registration {
                url: "http://test.example.com/register".to_string(),
                cert: String::new(),
                uuid: "test-uuid-123".to_string(),
            },
        });

        let result = attestation_key_handle_with_deps(
            &attestation_key,
            &generator,
            http_client_factory,
            &filesystem,
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed with status: 500")
        );
        assert!(filesystem.written.borrow().is_empty());
    }

    #[test]
    fn test_attestation_key_handle_registration_succeeds_after_retries() {
        let generator = MockAttestationKeyGenerator {
            response: Ok("mock_attestation_key".to_string()),
        };
        let filesystem = MockFileSystem {
            write_result: Ok(()),
            written: std::cell::RefCell::new(Vec::new()),
        };
        let http_client_factory = move |_cert: &str| -> Result<Box<dyn HttpClient>> {
            Ok(Box::new(MockHttpClient {
                responses: vec![Ok(500), Ok(500), Ok(200)],
                call_count: std::cell::RefCell::new(0),
            }))
        };

        let attestation_key = Some(AttestationKey {
            registration: Registration {
                url: "http://test.example.com/register".to_string(),
                cert: String::new(),
                uuid: "test-uuid-123".to_string(),
            },
        });

        let result = attestation_key_handle_with_deps(
            &attestation_key,
            &generator,
            http_client_factory,
            &filesystem,
        );

        assert!(result.is_ok());
        assert_eq!(filesystem.written.borrow().len(), 1);
        assert_eq!(filesystem.written.borrow()[0], AK_REGISTERD);
    }

    #[test]
    fn test_attestation_key_handle_generation_fails() {
        let generator = MockAttestationKeyGenerator {
            response: Err(anyhow!("Failed to generate attestation key")),
        };
        let filesystem = MockFileSystem {
            write_result: Ok(()),
            written: std::cell::RefCell::new(Vec::new()),
        };
        let http_client_factory = |_cert: &str| -> Result<Box<dyn HttpClient>> {
            panic!("HTTP client should not be called when key generation fails");
        };

        let attestation_key = Some(AttestationKey {
            registration: Registration {
                url: "http://test.example.com/register".to_string(),
                cert: String::new(),
                uuid: "test-uuid-123".to_string(),
            },
        });

        let result = attestation_key_handle_with_deps(
            &attestation_key,
            &generator,
            http_client_factory,
            &filesystem,
        );

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to generate attestation key"
        );
        assert!(filesystem.written.borrow().is_empty());
    }

    #[test]
    fn test_attestation_key_handle_http_client_error() {
        let generator = MockAttestationKeyGenerator {
            response: Ok("mock_attestation_key".to_string()),
        };
        let filesystem = MockFileSystem {
            write_result: Ok(()),
            written: std::cell::RefCell::new(Vec::new()),
        };
        let http_client_factory = move |_cert: &str| -> Result<Box<dyn HttpClient>> {
            Ok(Box::new(MockHttpClient {
                responses: vec![
                    Err(anyhow!("Network error")),
                    Err(anyhow!("Network error")),
                    Err(anyhow!("Network error")),
                    Err(anyhow!("Network error")),
                    Err(anyhow!("Network error")),
                    Err(anyhow!("Network error")),
                    Err(anyhow!("Network error")),
                    Err(anyhow!("Network error")),
                    Err(anyhow!("Network error")),
                    Err(anyhow!("Network error")),
                ],
                call_count: std::cell::RefCell::new(0),
            }))
        };

        let attestation_key = Some(AttestationKey {
            registration: Registration {
                url: "http://test.example.com/register".to_string(),
                cert: String::new(),
                uuid: "test-uuid-123".to_string(),
            },
        });

        let result = attestation_key_handle_with_deps(
            &attestation_key,
            &generator,
            http_client_factory,
            &filesystem,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Network error"));
        assert!(filesystem.written.borrow().is_empty());
    }

    #[test]
    fn test_attestation_key_handle_filesystem_write_fails() {
        let generator = MockAttestationKeyGenerator {
            response: Ok("mock_attestation_key".to_string()),
        };
        let filesystem = MockFileSystem {
            write_result: Err(anyhow!("Permission denied")),
            written: std::cell::RefCell::new(Vec::new()),
        };
        let http_client_factory = move |_cert: &str| -> Result<Box<dyn HttpClient>> {
            Ok(Box::new(MockHttpClient {
                responses: vec![Ok(200)],
                call_count: std::cell::RefCell::new(0),
            }))
        };

        let attestation_key = Some(AttestationKey {
            registration: Registration {
                url: "http://test.example.com/register".to_string(),
                cert: String::new(),
                uuid: "test-uuid-123".to_string(),
            },
        });

        let result = attestation_key_handle_with_deps(
            &attestation_key,
            &generator,
            http_client_factory,
            &filesystem,
        );

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Permission denied");
    }
}
