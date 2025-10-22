use tss_esapi::attributes::{SessionAttributesBuilder, ObjectAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::interface_types::{
    algorithm::{HashingAlgorithm, PublicAlgorithm}, resource_handles::{Provision, Hierarchy}, dynamic_handles::Persistent 
};
use tss_esapi::structures::{
     CreatePrimaryKeyResult, PublicBuilder, SymmetricDefinition,
     PublicRsaParametersBuilder, RsaScheme, HashScheme, RsaExponent
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::{Context as TssContext};
use std::str::FromStr;
use anyhow::{anyhow, Context, Result};
use std::env;
use log;
use tss_esapi::handles::{PersistentTpmHandle, TpmHandle};

const AA_TPM_DEVICE_ENV: &str = "AA_TPM_DEVICE";


/// Creates a TCTI configuration from a device path string.
pub fn create_tcti(tpm_device: &str) -> Result<TctiNameConf> {
    log::info!("Creating TCTI configuration for device: {}", tpm_device);
    let tcti_conf_str = format!("device:{}", tpm_device);
    TctiNameConf::from_str(&tcti_conf_str).context(format!(
        "Failed to create TCTI config from: {}",
        tcti_conf_str
    ))
}

/// Creates a TSS context without a session, for a specific TPM device.
pub fn create_ctx_without_session(tpm_device: &str) -> Result<TssContext> {
    let tcti = create_tcti(tpm_device)?;
    TssContext::new(tcti).context(format!(
        "Failed to create TSS context for device: {}",
        tpm_device
    ))
}

/// Creates a TSS context with a session, for a specific TPM device.
pub fn create_ctx_with_session(tpm_device: &str) -> Result<TssContext> {
    let mut ctx = create_ctx_without_session(tpm_device)?;

    let session = ctx.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::Xor {
            hashing_algorithm: HashingAlgorithm::Sha256,
        },
        HashingAlgorithm::Sha256,
    )?;
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    let valid_session = session.ok_or(anyhow!("Failed to start auth session"))?;

    ctx.tr_sess_set_attributes(valid_session, session_attributes, session_attributes_mask)?;
    ctx.set_sessions((session, None, None));

    Ok(ctx)
}

/// Detect the TPM device to use.
/// Priority: 1. AA_TPM_DEVICE env var, 2. /dev/tpm[0..2]
pub fn detect_tpm_device() -> Option<String> {
    // Check environment variable first
    if let Ok(dev) = env::var(AA_TPM_DEVICE_ENV) {
        return match std::path::Path::new(&dev).exists() {
            true => {
                log::info!(
                    "TPM device detected from {} env var: {}",
                    AA_TPM_DEVICE_ENV,
                    dev
                );
                Some(dev)
            }
            false => {
                log::warn!(
                    "{} env set to '{}', but device does not exist",
                    AA_TPM_DEVICE_ENV,
                    dev
                );
                None
            }
        };
    }

    // Check predefined TPM device paths
    for &dev in &["/dev/tpm0", "/dev/tpm1", "/dev/tpm2"] {
        if std::path::Path::new(dev).exists() {
            log::info!("TPM device detected: {}", dev);
            return Some(dev.to_string());
        }
    }

    log::warn!("No TPM device (/dev/tpm[0..2]) detected");
    None
}

pub fn create_primary_ak(ctx: &mut TssContext) -> Result<CreatePrimaryKeyResult> {

    // Build object attributes per tpm2-tools flags
    let obj_attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_restricted(true)
        .with_sign_encrypt(true)
        .with_user_with_auth(true)
        .build()?;
    // Build RSA parameters
    let hash_scheme = HashScheme::new(HashingAlgorithm::Sha256);
    let rsa_params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::RsaSsa(hash_scheme))
        .with_key_bits(2048.try_into()?)
        .with_exponent(RsaExponent::default())
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(true)
        .build()?;
    
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(obj_attrs)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(Default::default())
        .build()?;
    
    let ak_primary = TssContext::create_primary(
        ctx,
        Hierarchy::Endorsement,
        public,
        None,
        None,
        None,
        None,
    )?;
    return Result::Ok(ak_primary);
    
}

pub fn persistent_ak(ak: &CreatePrimaryKeyResult, tpm_handler: u32, mut ctx: TssContext) -> Result<()> {

    let persistent_handle  =  PersistentTpmHandle::new(tpm_handler)?;
    // Check if handle is already in use 
    match ctx.tr_from_tpm_public(TpmHandle::from(persistent_handle)) {
        Ok(_) => {
            log::warn!("Handle {:#x} already exists and is in use", tpm_handler);
            return Ok(());
        }
        Err(_) => {
            log::info!("Handle {:#x} is available, proceeding to make AK persistent", tpm_handler);
        }
    }

    // Make the AK persistent at the specified handle
    log::info!("Making AK persistent at handle {:#x}", tpm_handler);
    ctx.evict_control(
        Provision::Owner,
        ak.key_handle.into(),
        Persistent::from(persistent_handle),
    )?;
    log::info!("AK successfully created and persisted at handle {:#x}", tpm_handler);

    Result::Ok(())
}





#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_make_persistent_ak() -> Result<(), Box<dyn std::error::Error>> {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
        let dev = detect_tpm_device().ok_or_else(|| anyhow!("No TPM device found"))?;
        let mut ctx = create_ctx_with_session(&dev)?;
        let ak = create_primary_ak(&mut ctx).expect("Failed to create primary AK");
        persistent_ak(&ak, 0x81010003,ctx).expect("Failed to make AK persistent");
        Ok(())
    }
}