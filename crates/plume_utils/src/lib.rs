mod bundle;
mod cgbi;
mod device;
pub mod discovery;
mod options;
mod package;
pub mod pairing;
mod signer;
mod tweak;

use std::collections::HashMap;
use std::path::Path;
pub use bundle::{Bundle, BundleType};
pub use device::{
    Device, DeviceTransport, TvosDeviceInfo, get_device_for_id, install_app_mac,
    synthetic_device_id,
};
pub use options::{
    SignerApp, // Supported app types
    SignerAppReal,
    SignerEmbedding,   // Embedding options
    SignerFeatures,    // Feature support options
    SignerInstallMode, // Installation mode
    SignerMode,        // Signing mode
    SignerOptions,     // Main
};
pub use package::Package;
pub use pairing::{PairingBackend, PairingFailure, PairingStage, ensure_pairing};
pub use signer::Signer;
pub use tweak::Tweak;

pub type Result<T> = std::result::Result<T, Error>;

use thiserror::Error as ThisError;
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Info.plist not found")]
    BundleInfoPlistMissing,
    // Device
    #[error("Bundle failed to rename, make sure its available: {0}")]
    BundleFailedToCopy(String),
    // Tweak
    #[error("Invalid tweak file path")]
    TweakInvalidPath,
    #[error("Tweak extraction failed: {0}")]
    TweakExtractionFailed(String),
    #[error("Unsupported file type: {0}")]
    UnsupportedFileType(String),

    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("Info.plist not found")]
    PackageInfoPlistMissing,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Plist error: {0}")]
    Plist(#[from] plist::Error),
    #[error("Core error: {0}")]
    Core(#[from] plume_core::Error),
    #[error("Idevice error: {0}")]
    Idevice(#[from] idevice::IdeviceError),
    #[error("Codesign error: {0}")]
    Codesign(#[from] plume_core::AppleCodesignError),
    #[error("Other error: {0}")]
    Other(String),
    #[error("Image error: {0}")]
    Image(#[from] image::ImageError),
}

pub trait PlistInfoTrait {
    fn get_name(&self) -> Option<String>;
    fn get_executable(&self) -> Option<String>;
    fn get_bundle_identifier(&self) -> Option<String>;
    fn get_bundle_name(&self) -> Option<String>;
    fn get_version(&self) -> Option<String>;
    fn get_build_version(&self) -> Option<String>;
}

pub async fn copy_dir_recursively(src: &Path, dst: &Path) -> Result<()> {
    use tokio::fs;

    fs::create_dir_all(dst).await?;
    let mut entries = fs::read_dir(src).await?;

    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_symlink() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                let target = fs::read_link(&src_path).await?;
                symlink(&target, &dst_path)?;
            }
        } else if file_type.is_dir() {
            Box::pin(copy_dir_recursively(&src_path, &dst_path)).await?;
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path).await?;
        }
    }

    Ok(())
}

pub use plume_core::is_valid_device_udid;

fn dedup_key_for_device(device: &Device) -> Option<String> {
    if is_valid_device_udid(&device.udid) {
        return Some(format!("udid:{}", device.udid.to_ascii_lowercase()));
    }

    if device.is_network() {
        return device
            .pairing_identity
            .as_deref()
            .filter(|identity| !identity.is_empty())
            .map(|identity| format!("pairing:{}", identity.to_ascii_lowercase()));
    }

    None
}

fn device_quality(device: &Device) -> usize {
    let mut score = 0;
    if is_valid_device_udid(&device.udid) {
        score += 100;
    }
    if device.is_network() && device.pairing_identity.is_some() {
        score += 40;
    }
    if device.usbmuxd_device.is_some() {
        score += 20;
    }
    score += device.product_type.is_some() as usize * 10;
    score += device.device_class.is_some() as usize * 8;
    score += device.os_version.is_some() as usize * 4;
    score += device.serial_number.is_some() as usize * 4;
    score += device.reconnect_address.is_some() as usize * 3;
    score += device.pairing_address.is_some() as usize * 2;
    score
}

pub fn deduplicate_devices(devices: impl IntoIterator<Item = Device>) -> Vec<Device> {
    let mut result = Vec::new();
    let mut indexes = HashMap::new();

    for device in devices {
        let Some(key) = dedup_key_for_device(&device) else {
            result.push(device);
            continue;
        };

        if let Some(index) = indexes.get(&key).copied() {
            if device_quality(&device) > device_quality(&result[index]) {
                result[index] = device;
            }
        } else {
            indexes.insert(key, result.len());
            result.push(device);
        }
    }

    result
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_000;
    const MB: u64 = 1_000 * KB;
    const GB: u64 = 1_000 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{} KB", bytes / KB)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_picks_a_unit_per_magnitude() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_000), "1 KB");
        assert_eq!(format_bytes(999_999), "999 KB");
        assert_eq!(format_bytes(1_000_000), "1.0 MB");
        assert_eq!(format_bytes(1_000_000_000), "1.0 GB");
    }

    #[test]
    fn format_bytes_rounds_to_one_decimal_at_megabytes() {
        assert_eq!(format_bytes(54_741_568), "54.7 MB");
    }

    #[test]
    fn validates_legacy_and_modern_udids() {
        assert!(is_valid_device_udid("00008110-000C25540CD1801E"));
        assert!(is_valid_device_udid("0123456789abcdef0123456789abcdef01234567"));
        assert!(!is_valid_device_udid("00:11:22:33:44:55"));
        assert!(!is_valid_device_udid("Apple-TV.local"));
    }

    #[test]
    fn deduplicates_authenticated_network_and_legacy_entries() {
        let cache_dir = std::env::temp_dir();
        let mut legacy = Device::new_tvos(
            "Living Room".to_string(),
            "Living-Room".to_string(),
            "192.0.2.10".parse().unwrap(),
            None,
            Some(49152),
            cache_dir.clone(),
        );
        legacy.udid = "00008110-000C25540CD1801E".to_string();
        legacy.product_type = Some("AppleTV14,1".to_string());
        let mut authenticated = legacy.clone();
        authenticated.reconnect_address = Some(("192.0.2.11".parse().unwrap(), 49152));
        authenticated.os_version = Some("26.6".to_string());

        let devices = deduplicate_devices([legacy, authenticated.clone()]);

        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].reconnect_address,
            authenticated.reconnect_address
        );
        assert_eq!(devices[0].os_version, authenticated.os_version);
    }

    #[test]
    fn deduplicates_unenriched_network_advertisements_by_pairing_identity() {
        let cache_dir = std::env::temp_dir();
        let first = Device::new_tvos(
            "Living Room".to_string(),
            "Living-Room".to_string(),
            "192.0.2.10".parse().unwrap(),
            Some(49153),
            None,
            cache_dir.clone(),
        );
        let second = Device::new_tvos(
            "living room".to_string(),
            "living-room".to_string(),
            "192.0.2.11".parse().unwrap(),
            None,
            Some(49152),
            cache_dir,
        );

        let devices = deduplicate_devices([first, second]);

        assert_eq!(devices.len(), 1);
    }
}
