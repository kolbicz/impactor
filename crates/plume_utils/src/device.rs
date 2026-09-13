use std::fmt;
use std::future::Future;
#[cfg(target_os = "macos")]
use std::io::Write;
use std::path::{Component, Path, PathBuf};
#[cfg(not(target_os = "macos"))]
use std::pin::Pin;
use std::time::Duration;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use idevice::core_device_proxy::CoreDeviceProxy;
use idevice::installation_proxy::InstallationProxyClient;
use idevice::lockdown::LockdownClient;
use idevice::misagent::MisagentClient;
use idevice::provider::UsbmuxdProvider;
use idevice::remote_pairing::{
    connect_tls_psk_tunnel_native, RemotePairingClient, RpPairingFile, RpPairingSocket,
    RpPairingSocketProvider,
};
#[cfg(not(target_os = "macos"))]
use idevice::remote_pairing::errors::RemotePairingError;
use idevice::rsd::RsdHandshake;
use idevice::tcp::adapter::Adapter;
use idevice::tcp::handle::AdapterHandle;
use idevice::usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdDevice};
use idevice::utils::installation;
use idevice::{IdeviceService, RemoteXpcClient, RsdService};
use plume_core::{MobileProvision, developer::DeveloperPlatform};

use crate::Error;
use crate::discovery::{DeviceDiscovery, DeviceType, PlatformDiscovery, REMOTEPAIRING_SERVICE};
use crate::options::SignerAppReal;
#[cfg(not(target_os = "macos"))]
use crate::pairing::{PairingBackend, PairingFailure, PairingStage, ensure_pairing};
use idevice::afc::opcode::AfcFopenMode;
use idevice::house_arrest::HouseArrestClient;
use idevice::usbmuxd::UsbmuxdConnection;
use plist::Value;
#[cfg(not(target_os = "macos"))]
use serde::Serialize;

pub const CONNECTION_LABEL: &str = "plume_info";
pub const INSTALLATION_LABEL: &str = "plume_install";
pub const HOUSE_ARREST_LABEL: &str = "plume_house_arrest";

#[cfg(not(target_os = "macos"))]
impl<'a, R: idevice::remote_pairing::RpPairingSocketProvider> PairingBackend
    for RemotePairingClient<'a, R>
{
    async fn verify(&mut self) -> Result<(), PairingFailure> {
        self.attempt_pair_verify()
            .await
            .map_err(|error| PairingFailure::Protocol(error.to_string()))?;
        self.validate_pairing()
            .await
            .map_err(|error| PairingFailure::Protocol(error.to_string()))
    }

    async fn pair(&mut self, pin: &str) -> Result<(), PairingFailure> {
        let pin = pin.to_string();
        RemotePairingClient::connect(
            self,
            |_| {
                let pin = pin.clone();
                async move { pin }
            },
            (),
        )
        .await
        .map_err(|error| match error {
            idevice::IdeviceError::RemotePairing(RemotePairingError::SrpAuthFailed) => {
                PairingFailure::WrongPin
            }
            error => PairingFailure::Protocol(error.to_string()),
        })
    }
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
struct SequencedTvosPairingSocket {
    inner: RpPairingSocket<tokio::net::TcpStream>,
    sequence_offset: usize,
}

#[cfg(not(target_os = "macos"))]
impl SequencedTvosPairingSocket {
    fn new(inner: RpPairingSocket<tokio::net::TcpStream>, sequence_offset: usize) -> Self {
        Self {
            inner,
            sequence_offset,
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl RpPairingSocketProvider for SequencedTvosPairingSocket {
    fn send_plain(
        &mut self,
        value: impl Serialize,
        seq: usize,
    ) -> Pin<Box<dyn Future<Output = Result<(), idevice::IdeviceError>> + Send + '_>> {
        self.inner.send_plain(value, seq + self.sequence_offset)
    }

    fn send_encrypted(
        &mut self,
        ciphertext: Vec<u8>,
        seq: usize,
    ) -> Pin<Box<dyn Future<Output = Result<(), idevice::IdeviceError>> + Send + '_>> {
        self.inner
            .send_encrypted(ciphertext, seq + self.sequence_offset)
    }

    fn recv_plain<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<plist::Value, idevice::IdeviceError>> + Send + 'a>> {
        self.inner.recv_plain()
    }

    fn serialize_bytes(b: &[u8]) -> plist::Value {
        RpPairingSocket::<tokio::net::TcpStream>::serialize_bytes(b)
    }

    fn deserialize_bytes(v: plist::Value) -> Option<Vec<u8>> {
        RpPairingSocket::<tokio::net::TcpStream>::deserialize_bytes(v)
    }
}

#[cfg(not(target_os = "macos"))]
struct TvosPairingBackend<'a> {
    client: RemotePairingClient<'a, SequencedTvosPairingSocket>,
}

#[cfg(not(target_os = "macos"))]
impl<'a> PairingBackend for TvosPairingBackend<'a> {
    async fn verify(&mut self) -> Result<(), PairingFailure> {
        self.client
            .attempt_pair_verify()
            .await
            .map_err(|error| PairingFailure::Protocol(error.to_string()))?;
        self.client
            .validate_pairing()
            .await
            .map_err(|error| PairingFailure::Protocol(error.to_string()))
    }

    async fn pair(&mut self, pin: &str) -> Result<(), PairingFailure> {
        let pin = pin.to_string();
        RemotePairingClient::pair(
            &mut self.client,
            |_| {
                let pin = pin.clone();
                async move { pin }
            },
            (),
        )
        .await
        .map_err(|error| match error {
            idevice::IdeviceError::RemotePairing(RemotePairingError::SrpAuthFailed) => {
                PairingFailure::WrongPin
            }
            error => PairingFailure::Protocol(error.to_string()),
        })
    }
}

#[cfg(not(target_os = "macos"))]
const TVOS_RP_PAIRING_WIRE_PROTOCOL_VERSION: i64 = 26;

#[cfg(not(target_os = "macos"))]
async fn begin_tvos_pairing(
    stream: tokio::net::TcpStream,
) -> Result<SequencedTvosPairingSocket, Error> {
    let correlation_identifier: String = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(6)
        .collect();
    let mut socket = RpPairingSocket::new(stream);
    socket
        .send_plain(tvos_pairing_handshake_request(&correlation_identifier), 0)
        .await?;
    let response = socket.recv_plain().await?;
    if !tvos_pairing_handshake_allows_pair_setup(&response) {
        return Err(Error::Other(
            "Apple TV did not advertise support for manual pairing".to_string(),
        ));
    }
    Ok(SequencedTvosPairingSocket::new(socket, 1))
}

#[cfg(target_os = "macos")]
async fn pair_tvos_with_devicectl<F, Fut>(
    device_name: &str,
    pin_provider: F,
    address: Option<(std::net::IpAddr, u16)>,
    cache_dir: &Path,
    cache_path: &Path,
) -> Result<RpPairingFile, Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = String>,
{
    let (pin_sender, pin_receiver) = std::sync::mpsc::sync_channel::<String>(1);
    let device_name = device_name.to_string();
    let mut pairing_task = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut child = std::process::Command::new("xcrun")
            .args([
                "devicectl",
                "manage",
                "pair",
                "--device",
                device_name.as_str(),
                "--timeout",
                "180",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|error| format!("Could not start xcrun devicectl: {error}"))?;

        let pin = loop {
            match pin_receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(pin) => break pin,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(status) = child
                        .try_wait()
                        .map_err(|error| format!("Could not check xcrun devicectl: {error}"))?
                    {
                        if status.success() {
                            return Ok(());
                        }
                        return Err(format!(
                            "xcrun devicectl pairing failed with status {status}"
                        ));
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("Apple TV pairing PIN was not provided".to_string());
                }
            }
        };
        if pin.is_empty() {
            let _ = child.kill();
            return Err("Apple TV pairing was cancelled".to_string());
        }
        if pin.len() != 6 || !pin.bytes().all(|byte| byte.is_ascii_digit()) {
            let _ = child.kill();
            return Err("Apple TV pairing PIN must contain exactly six digits".to_string());
        }

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "xcrun devicectl did not expose standard input".to_string())?;
        stdin
            .write_all(format!("{pin}\n").as_bytes())
            .map_err(|error| format!("Could not provide the Apple TV pairing PIN: {error}"))?;
        drop(stdin);

        let status = child
            .wait()
            .map_err(|error| format!("Could not wait for xcrun devicectl: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("xcrun devicectl pairing failed with status {status}"))
        }
    });

    let pin_future = pin_provider();
    tokio::pin!(pin_future);
    let pairing_result = tokio::select! {
        result = &mut pairing_task => result,
        pin = &mut pin_future => {
            if pin_sender.send(pin).is_err() {
                return Err(Error::Other(
                    "xcrun devicectl exited before the Apple TV pairing PIN was provided".to_string(),
                ));
            }
            pairing_task.await
        }
    };
    pairing_result
        .map_err(|error| Error::Other(format!("Apple TV pairing task failed: {error}")))?
        .map_err(Error::Other)?;

    try_import_external_pairing_at(address, cache_dir, cache_path)
        .await?
        .ok_or_else(|| {
            Error::Other(
                "Apple TV pairing completed in Xcode but its pairing record could not be imported"
                    .to_string(),
            )
        })
}

#[cfg(not(target_os = "macos"))]
fn tvos_pairing_handshake_request(correlation_identifier: &str) -> Value {
    let mut host_options = plist::Dictionary::new();
    host_options.insert("attemptPairVerify".to_string(), Value::Boolean(false));

    let mut correlation = plist::Dictionary::new();
    correlation.insert(
        "value".to_string(),
        Value::String(correlation_identifier.to_string()),
    );

    let mut handshake = plist::Dictionary::new();
    handshake.insert("hostOptions".to_string(), Value::Dictionary(host_options));
    handshake.insert(
        "correlationIdentifier".to_string(),
        Value::Dictionary(correlation),
    );
    handshake.insert(
        "wireProtocolVersion".to_string(),
        Value::Integer(TVOS_RP_PAIRING_WIRE_PROTOCOL_VERSION.into()),
    );

    let mut handshake_container = plist::Dictionary::new();
    handshake_container.insert("_0".to_string(), Value::Dictionary(handshake));

    let mut request = plist::Dictionary::new();
    request.insert(
        "handshake".to_string(),
        Value::Dictionary(handshake_container),
    );

    let mut request_container = plist::Dictionary::new();
    request_container.insert("_0".to_string(), Value::Dictionary(request));

    let mut root = plist::Dictionary::new();
    root.insert("request".to_string(), Value::Dictionary(request_container));
    Value::Dictionary(root)
}

#[cfg(not(target_os = "macos"))]
fn tvos_pairing_handshake_allows_pair_setup(response: &Value) -> bool {
    response
        .as_dictionary()
        .and_then(|value| value.get("response"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("_1"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("handshake"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("_0"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("deviceOptions"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("allowsPairSetup"))
        .and_then(Value::as_boolean)
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTransport {
    Usbmuxd,
    RemotePairing,
    CoreDevice,
    LocalMac,
    Unavailable,
}

macro_rules! get_dict_string {
    ($dict:expr, $key:expr) => {
        $dict
            .as_dictionary()
            .and_then(|dict| dict.get($key))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "".to_string())
    };
}

#[derive(Debug, Clone)]
pub struct Device {
    pub name: String,
    pub udid: String,
    pub product_type: Option<String>,
    pub device_class: Option<String>,
    pub os_version: Option<String>,
    pub serial_number: Option<String>,
    pub device_id: u32,
    pub usbmuxd_device: Option<UsbmuxdDevice>,
    // On x86_64 macs, `is_mac` variable should never be true
    // since its only true if the device is added manually.
    pub is_mac: bool,
    pub pairing_address: Option<(std::net::IpAddr, u16)>,
    pub reconnect_address: Option<(std::net::IpAddr, u16)>,
    pub pairing_identity: Option<String>,
    pub pairing_cache_dir: Option<PathBuf>,
    pub core_device_authenticated: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TvosDeviceInfo {
    pub name: Option<String>,
    pub udid: Option<String>,
    pub product_type: Option<String>,
    pub device_class: Option<String>,
    pub os_version: Option<String>,
    pub serial_number: Option<String>,
}

impl TvosDeviceInfo {
    pub fn from_rsd_properties(props: &std::collections::HashMap<String, plist::Value>) -> Self {
        let as_string = |key: &str| -> Option<String> {
            props
                .get(key)
                .and_then(|v| v.as_string())
                .map(str::to_string)
        };

        TvosDeviceInfo {
            name: as_string("DeviceName").or_else(|| as_string("Name")),
            udid: as_string("UniqueDeviceID"),
            product_type: as_string("ProductType"),
            device_class: as_string("DeviceClass"),
            os_version: as_string("OSVersion")
                .or_else(|| as_string("HumanReadableProductVersionString")),
            serial_number: as_string("SerialNumber"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreDeviceTransport {
    pairing_address: Option<(std::net::IpAddr, u16)>,
    reconnect_address: Option<(std::net::IpAddr, u16)>,
    pairing_identity: Option<String>,
    udid: String,
    cache_dir: PathBuf,
    authenticated: bool,
}

impl CoreDeviceTransport {
    fn new(device: &Device, cache_dir: PathBuf) -> Result<Self, Error> {
        if device.usbmuxd_device.is_some() {
            return Err(Error::Other(
                "CoreDevice transport cannot wrap a usbmuxd device".to_string(),
            ));
        }
        Ok(Self {
            pairing_address: device.pairing_address,
            reconnect_address: device.reconnect_address,
            pairing_identity: device.pairing_identity.clone(),
            udid: device.udid.clone(),
            cache_dir,
            authenticated: device.core_device_authenticated,
        })
    }

    pub fn kind(&self) -> DeviceTransport {
        if self.authenticated {
            DeviceTransport::CoreDevice
        } else if self.pairing_address.is_some() || self.reconnect_address.is_some() {
            DeviceTransport::RemotePairing
        } else {
            DeviceTransport::Unavailable
        }
    }

    pub async fn connect(&self) -> Result<(AdapterHandle, RsdHandshake), Error> {
        establish_core_device_tunnel(
            self.pairing_address,
            self.reconnect_address,
            self.pairing_identity.as_deref(),
            &self.udid,
            &self.cache_dir,
        )
        .await
    }
}

pub fn synthetic_device_id(pairing_identity: &str) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in pairing_identity.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash |= 0x8000_0000;

    if hash == u32::MAX {
        hash = 0x8000_0000;
    }

    hash
}

impl Device {
    pub fn is_wifi(&self) -> bool {
        self.usbmuxd_device
            .as_ref()
            .is_some_and(|device| matches!(&device.connection_type, Connection::Network(_)))
    }

    pub async fn new(usbmuxd_device: UsbmuxdDevice) -> Self {
        let values = Self::get_values_from_usbmuxd_device(&usbmuxd_device)
            .await
            .ok();
        let name = values
            .as_ref()
            .map(|values| get_dict_string!(values, "DeviceName"))
            .unwrap_or_default();
        let product_type = values
            .as_ref()
            .map(|values| get_dict_string!(values, "ProductType"))
            .filter(|value| !value.is_empty());
        let device_class = values
            .as_ref()
            .map(|values| get_dict_string!(values, "DeviceClass"))
            .filter(|value| !value.is_empty());
        let os_version = values
            .as_ref()
            .map(|values| get_dict_string!(values, "ProductVersion"))
            .filter(|value| !value.is_empty());
        let serial_number = values
            .as_ref()
            .map(|values| get_dict_string!(values, "SerialNumber"))
            .filter(|value| !value.is_empty());

        Device {
            name,
            udid: usbmuxd_device.udid.clone(),
            product_type,
            device_class,
            os_version,
            serial_number,
            device_id: usbmuxd_device.device_id.clone(),
            usbmuxd_device: Some(usbmuxd_device),
            is_mac: false,
            pairing_address: None,
            reconnect_address: None,
            pairing_identity: None,
            pairing_cache_dir: None,
            core_device_authenticated: false,
        }
    }

    async fn get_values_from_usbmuxd_device(
        device: &UsbmuxdDevice,
    ) -> Result<Value, Error> {
        let mut lockdown =
            LockdownClient::connect(&device.to_provider(UsbmuxdAddr::default(), CONNECTION_LABEL))
                .await?;
        Ok(lockdown.get_value(None, None).await?)
    }

    pub fn new_tvos(
        name: String,
        pairing_identity: String,
        ip: std::net::IpAddr,
        pairing_port: Option<u16>,
        reconnect_port: Option<u16>,
        cache_dir: PathBuf,
    ) -> Self {
        Self::new_tvos_with_addresses(
            name,
            pairing_identity,
            pairing_port.map(|port| (ip, port)),
            reconnect_port.map(|port| (ip, port)),
            cache_dir,
        )
    }

    pub fn new_tvos_with_addresses(
        name: String,
        pairing_identity: String,
        pairing_address: Option<(std::net::IpAddr, u16)>,
        reconnect_address: Option<(std::net::IpAddr, u16)>,
        cache_dir: PathBuf,
    ) -> Self {
        Device {
            name,
            udid: String::new(),
            product_type: None,
            device_class: Some("AppleTV".to_string()),
            os_version: None,
            serial_number: None,
            device_id: 0,
            usbmuxd_device: None,
            is_mac: false,
            pairing_address,
            reconnect_address,
            pairing_identity: Some(pairing_identity),
            pairing_cache_dir: Some(cache_dir),
            core_device_authenticated: false,
        }
    }

    pub(crate) fn pairing_cache_path(&self, cache_dir: &Path) -> Result<PathBuf, Error> {
        pairing_cache_path_for(self.pairing_identity.as_deref(), &self.udid, cache_dir)
    }

    pub fn is_tvos(&self) -> bool {
        self.developer_platform() == DeveloperPlatform::Tvos
    }

    pub fn developer_platform(&self) -> DeveloperPlatform {
        DeveloperPlatform::from_device_metadata(
            self.product_type.as_deref(),
            self.device_class.as_deref(),
            self.is_network() || self.pairing_identity.is_some(),
        )
    }

    pub fn is_network(&self) -> bool {
        matches!(
            self.transport(),
            DeviceTransport::RemotePairing | DeviceTransport::CoreDevice
        )
    }

    pub fn transport(&self) -> DeviceTransport {
        if self.usbmuxd_device.is_some() {
            DeviceTransport::Usbmuxd
        } else if self.core_device_authenticated {
            DeviceTransport::CoreDevice
        } else if self.pairing_address.is_some() || self.reconnect_address.is_some() {
            DeviceTransport::RemotePairing
        } else if self.is_mac {
            DeviceTransport::LocalMac
        } else {
            DeviceTransport::Unavailable
        }
    }

    pub fn core_device_transport(
        &self,
        cache_dir: PathBuf,
    ) -> Result<CoreDeviceTransport, Error> {
        CoreDeviceTransport::new(self, cache_dir)
    }

    pub async fn installed_apps(&self) -> Result<Vec<SignerAppReal>, Error> {
        let apps = if let Some(device) = &self.usbmuxd_device {
            let provider = device.to_provider(
                UsbmuxdAddr::from_env_var().unwrap_or_default(),
                INSTALLATION_LABEL,
            );
            let mut ic = InstallationProxyClient::connect(&provider).await?;
            ic.get_apps(Some("User"), None).await?
        } else if self.is_network() {
            let cache_dir = self.pairing_cache_dir.clone().ok_or_else(|| {
                Error::Other("Network Apple TV has no pairing cache directory".to_string())
            })?;
            let transport = self.core_device_transport(cache_dir)?;
            let (mut adapter, mut handshake) = transport.connect().await?;
            let mut ic = InstallationProxyClient::connect_rsd(&mut adapter, &mut handshake).await?;
            ic.get_apps(Some("User"), None).await?
        } else {
            return Err(Error::Other("Device has no installation transport".to_string()));
        };

        let mut found_apps = Vec::new();

        for (bundle_id, info) in apps {
            let app_name = get_app_name_from_info(&info);
            let signer_app = SignerAppReal::from_bundle_identifier_and_name(
                Some(bundle_id.as_str()),
                app_name.as_deref(),
            );

            if signer_app.app.supports_pairing_file_alt()
                && !found_apps
                    .iter()
                    .any(|a: &SignerAppReal| a.bundle_id == signer_app.bundle_id)
            {
                found_apps.push(signer_app);
            }
        }

        Ok(found_apps)
    }

    pub async fn is_app_installed(&self, bundle_id: &str) -> Result<bool, Error> {
        let apps = if let Some(device) = &self.usbmuxd_device {
            let provider = device.to_provider(
                UsbmuxdAddr::from_env_var().unwrap_or_default(),
                INSTALLATION_LABEL,
            );
            let mut ic = InstallationProxyClient::connect(&provider).await?;
            ic.get_apps(Some("User"), None).await?
        } else if self.is_network() {
            let cache_dir = self.pairing_cache_dir.clone().ok_or_else(|| {
                Error::Other("Network Apple TV has no pairing cache directory".to_string())
            })?;
            let transport = self.core_device_transport(cache_dir)?;
            let (mut adapter, mut handshake) = transport.connect().await?;
            let mut ic = InstallationProxyClient::connect_rsd(&mut adapter, &mut handshake).await?;
            ic.get_apps(Some("User"), None).await?
        } else {
            return Err(Error::Other("Device has no installation transport".to_string()));
        };

        Ok(apps.contains_key(bundle_id))
    }

    pub async fn install_profile(&self, profile: &MobileProvision) -> Result<(), Error> {
        if let Some(device) = &self.usbmuxd_device {
            let provider = device.to_provider(
                UsbmuxdAddr::from_env_var().unwrap_or_default(),
                INSTALLATION_LABEL,
            );
            let mut mc = MisagentClient::connect(&provider).await?;
            mc.install(profile.data.clone()).await?;
        } else if self.is_network() {
            let cache_dir = self.pairing_cache_dir.clone().ok_or_else(|| {
                Error::Other("Network Apple TV has no pairing cache directory".to_string())
            })?;
            let transport = self.core_device_transport(cache_dir)?;
            let (mut adapter, mut handshake) = transport.connect().await?;
            let mut mc = MisagentClient::connect_rsd(&mut adapter, &mut handshake).await?;
            mc.install(profile.data.clone()).await?;
        } else {
            return Err(Error::Other("Device has no installation transport".to_string()));
        }

        Ok(())
    }

    pub async fn pair(&self) -> Result<(), Error> {
        if self.usbmuxd_device.is_none() {
            return Err(Error::Other("Device is not connected via USB".to_string()));
        }

        let mut usbmuxd = UsbmuxdConnection::default().await?;

        let provider = self.usbmuxd_device.clone().unwrap().to_provider(
            UsbmuxdAddr::from_env_var().unwrap_or_default(),
            INSTALLATION_LABEL,
        );

        let mut lc = LockdownClient::connect(&provider).await?;
        let id = uuid::Uuid::new_v4().to_string().to_uppercase();
        let buid = usbmuxd.get_buid().await?;
        let mut pairing_file = lc.pair(id, buid, None).await?;
        pairing_file.udid = Some(self.udid.clone());
        let pairing_file = pairing_file.serialize()?;

        usbmuxd.save_pair_record(&self.udid, pairing_file).await?;

        Ok(())
    }

    pub async fn install_pairing_record(
        &self,
        identifier: &String,
        path: &str,
    ) -> Result<(), Error> {
        if self.usbmuxd_device.is_none() {
            return Err(Error::Other("Device is not connected via USB".to_string()));
        }

        let mut usbmuxd = UsbmuxdConnection::default().await?;
        let provider = self
            .usbmuxd_device
            .clone()
            .unwrap()
            .to_provider(UsbmuxdAddr::default(), HOUSE_ARREST_LABEL);
        let mut pairing_file = usbmuxd.get_pair_record(&self.udid).await?;

        // saving pairing record requires enabling wifi debugging
        // since operations are done over wifi
        let mut lc = LockdownClient::connect(&provider).await?;
        lc.start_session(&pairing_file).await.ok();
        lc.set_value(
            "EnableWifiDebugging",
            true.into(),
            Some("com.apple.mobile.wireless_lockdown"),
        )
        .await
        .ok();

        pairing_file.udid = Some(self.udid.clone());

        let hc = HouseArrestClient::connect(&provider).await?;
        let mut ac = hc.vend_documents(identifier.clone()).await?;
        if let Some(parent) = Path::new(path).parent() {
            let mut current = String::new();
            let has_root = parent.has_root();

            for component in parent.components() {
                if let Component::Normal(dir) = component {
                    if has_root && current.is_empty() {
                        current.push('/');
                    } else if !current.is_empty() && !current.ends_with('/') {
                        current.push('/');
                    }

                    current.push_str(&dir.to_string_lossy());
                    ac.mk_dir(&current).await?;
                }
            }
        }

        let mut f = ac.open(path, AfcFopenMode::Wr).await?;
        f.write_entire(&pairing_file.serialize().unwrap()).await?;

        Ok(())
    }

    pub async fn install_remote_pairing_record(
        &self,
        identifier: &String,
        path: &str,
        path_to_store: PathBuf,
    ) -> Result<(), Error> {
        if self.usbmuxd_device.is_none() {
            return Err(Error::Other("Device is not connected via USB".to_string()));
        }

        let provider = self
            .usbmuxd_device
            .clone()
            .unwrap()
            .to_provider(UsbmuxdAddr::default(), HOUSE_ARREST_LABEL);

        let pairing_file = self.get_rsd_pairing_file(&provider, path_to_store).await?;

        let hc = HouseArrestClient::connect(&provider).await?;
        let mut ac = hc.vend_documents(identifier.clone()).await?;
        if let Some(parent) = Path::new(path).parent() {
            let mut current = String::new();
            let has_root = parent.has_root();

            for component in parent.components() {
                if let Component::Normal(dir) = component {
                    if has_root && current.is_empty() {
                        current.push('/');
                    } else if !current.is_empty() && !current.ends_with('/') {
                        current.push('/');
                    }

                    current.push_str(&dir.to_string_lossy());
                    ac.mk_dir(&current).await?;
                }
            }
        }

        let mut f = ac.open(path, AfcFopenMode::Wr).await?;
        f.write_entire(&pairing_file.to_bytes()).await?;

        Ok(())
    }

    async fn get_rsd_pairing_file(
        &self,
        provider: &UsbmuxdProvider,
        path: PathBuf,
    ) -> Result<RpPairingFile, Error> {
        let pairing_file_path = path.join(format!("plume_{}.plist", self.udid));

        if pairing_file_path.exists() {
            return Ok(RpPairingFile::read_from_file(pairing_file_path).await?);
        } else {
            let cdp = CoreDeviceProxy::connect(provider).await?;
            let cdp_port = cdp.tunnel_info().server_rsd_port;
            let cdp_adapter = cdp.create_software_tunnel()?;
            let mut cdp_adapter = cdp_adapter.to_async_handle();

            let cdp_stream = cdp_adapter.connect(cdp_port).await?;
            let cdp_handshake = RsdHandshake::new(cdp_stream).await?;

            let tunnel_service = cdp_handshake
                .services
                .get("com.apple.internal.dt.coredevice.untrusted.tunnelservice")
                .ok_or_else(|| Error::Other("Tunnel service not found".to_string()))?;

            let tunnel_service_stream = cdp_adapter.connect(tunnel_service.port).await?;
            let mut remote_xpc = RemoteXpcClient::new(tunnel_service_stream).await?;
            remote_xpc.do_handshake().await?;
            let _ = remote_xpc.recv_root().await;

            let suffix: String = uuid::Uuid::new_v4()
                .simple()
                .to_string()
                .chars()
                .take(6)
                .collect();

            let hostname = format!("plume-{}", suffix);

            let mut pairing_file = RpPairingFile::generate(&hostname);
            let mut pairing_client =
                RemotePairingClient::new(remote_xpc, &hostname, &mut pairing_file);
            pairing_client
                .connect(async |_| "000000".to_string(), ())
                .await?;

            let tunnel_service_stream = cdp_adapter.connect(tunnel_service.port).await?;
            let mut remote_xpc = RemoteXpcClient::new(tunnel_service_stream).await?;
            remote_xpc.do_handshake().await?;
            let _ = remote_xpc.recv_root().await;
            let mut pairing_client =
                RemotePairingClient::new(remote_xpc, &hostname, &mut pairing_file);
            pairing_client
                .connect(async |_| "000000".to_string(), ())
                .await?;

            write_pairing_file(&pairing_file, &path, &pairing_file_path).await?;

            Ok(pairing_file)
        }
    }

    async fn try_import_external_pairing(
        &self,
        cache_dir: &Path,
        cache_path: &Path,
    ) -> Result<Option<RpPairingFile>, Error> {
        try_import_external_pairing_at(
            self.reconnect_address.or(self.pairing_address),
            cache_dir,
            cache_path,
        )
        .await
    }

    pub async fn pair_tvos<F, Fut>(
        &mut self,
        pin_provider: F,
        cache_dir: PathBuf,
    ) -> Result<RpPairingFile, Error>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = String>,
    {
        let cache_path = self.pairing_cache_path(&cache_dir)?;

        let cached_pairing_file = if cache_path.exists() {
            match RpPairingFile::read_from_file(&cache_path).await {
                Ok(pairing_file) => Some(pairing_file),
                Err(error) => {
                    log::warn!(
                        "Removing unreadable Apple TV pairing record at {}: {error}",
                        cache_path.display()
                    );
                    let _ = tokio::fs::remove_file(&cache_path).await;
                    None
                }
            }
        } else {
            None
        };

        if cached_pairing_file.is_none() {
            if let Some(pairing_file) =
                self.try_import_external_pairing(&cache_dir, &cache_path).await?
            {
                return self.finish_tvos_pairing(pairing_file).await;
            }
        }

        let action = pairing_action(
            cached_pairing_file.is_some(),
            self.pairing_address.is_some(),
            self.reconnect_address.is_some(),
        )
        .map_err(Error::Other)?;

        if action == PairingAction::Reconnect {
            let (ip, port) = self
                .reconnect_address
                .or(self.pairing_address)
                .expect("pairing_action guarantees an address");
            let addr = std::net::SocketAddr::new(ip, port);
            log::info!("tvOS pairing: reconnecting to {addr}");
            let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
                Error::Other(format!(
                    "Failed to reconnect to Apple TV at {addr}: {e}; scan again if the device changed its advertised address"
                ))
            })?;
            let mut pairing_file = cached_pairing_file
                .expect("pairing_action selected reconnect with a cached pairing file");
            let sending_host = pairing_file.identifier.clone();
            let mut pairing_client =
                RemotePairingClient::new(RpPairingSocket::new(stream), &sending_host, &mut pairing_file);

            let reconnect_result = match pairing_client.attempt_pair_verify().await {
                Ok(_) => pairing_client.validate_pairing().await,
                Err(error) => Err(error),
            };
            drop(pairing_client);

            if reconnect_result.is_ok() {
                write_pairing_file(&pairing_file, &cache_dir, &cache_path).await?;
                log::info!("tvOS pairing: cached record reconnected without a PIN");
                return self.finish_tvos_pairing(pairing_file).await;
            }

            if cache_path.exists() {
                log::warn!(
                    "Cached Apple TV pairing record at {} is stale; removing it",
                    cache_path.display()
                );
                let _ = tokio::fs::remove_file(&cache_path).await;
            }
            if let Some(pairing_file) =
                self.try_import_external_pairing(&cache_dir, &cache_path).await?
            {
                log::info!("tvOS pairing: recovered an existing native pairing record");
                return self.finish_tvos_pairing(pairing_file).await;
            }
        }

        #[cfg(target_os = "macos")]
        {
            let pairing_file = pair_tvos_with_devicectl(
                &self.name,
                pin_provider,
                self.reconnect_address.or(self.pairing_address),
                &cache_dir,
                &cache_path,
            )
            .await?;
            log::info!("tvOS pairing: imported the native Xcode pairing record");
            return self.finish_tvos_pairing(pairing_file).await;
        }

        #[cfg(not(target_os = "macos"))]
        {
        let (ip, port) = self.pairing_address.ok_or_else(|| {
            Error::Other(
                "Apple TV pairing requires its manual-pairing service. On the Apple TV, open Settings \
                 > Remotes and Devices > Remote App and Devices and wait for \"Waiting to Pair...\", \
                 then scan again."
                    .to_string(),
            )
        })?;

        let addr = std::net::SocketAddr::new(ip, port);
        log::info!("tvOS pairing: connecting to {addr}");
        let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
            Error::Other(format!(
                "Failed to connect to Apple TV at {addr}: {e}. The manual-pairing port changes \
                 each time the Apple TV re-advertises, so a stale scan result will not connect - \
                 scan again immediately before pairing."
            ))
        })?;
        log::info!("tvOS pairing: TCP connected to {addr}, starting RPPairing handshake");

        let local_hostname = local_remote_pairing_hostname().ok_or_else(|| {
            Error::Other("Could not determine the Mac hostname for Apple TV pairing".to_string())
        })?;
        let sending_host = local_remote_pairing_host().unwrap_or_else(|| local_hostname.clone());
        let mut pairing_file = RpPairingFile::generate(&local_hostname);
        let conn = begin_tvos_pairing(stream).await?;
        let pairing_client = RemotePairingClient::new(conn, &sending_host, &mut pairing_file);
        let mut pairing_backend = TvosPairingBackend {
            client: pairing_client,
        };
        let stage = ensure_pairing(
            &mut pairing_backend,
            false,
            true,
            false,
            pin_provider,
        )
        .await
        .map_err(pairing_failure_to_error)?;
        if stage != PairingStage::Paired {
            return Err(Error::Other(
                "Apple TV pairing did not complete a new pairing".to_string(),
            ));
        }
        log::info!("tvOS pairing: handshake succeeded, caching pairing file");

        write_pairing_file(&pairing_file, &cache_dir, &cache_path).await?;

        self.finish_tvos_pairing(pairing_file).await
        }
    }

    async fn finish_tvos_pairing(
        &mut self,
        pairing_file: RpPairingFile,
    ) -> Result<RpPairingFile, Error> {
        self.refresh_tvos_reconnect_address(Duration::from_secs(5))
            .await?;
        Ok(pairing_file)
    }

    pub async fn refresh_tvos_reconnect_address(
        &mut self,
        timeout: Duration,
    ) -> Result<(), Error> {
        let pairing_identity = self
            .pairing_identity
            .as_deref()
            .filter(|identity| !identity.is_empty())
            .map(str::to_ascii_lowercase);
        let known_ip = self
            .pairing_address
            .or(self.reconnect_address)
            .map(|(ip, _)| ip);

        let discovered = PlatformDiscovery::new().discover(timeout).await?;
        let candidate = discovered
            .into_iter()
            .filter(|device| {
                device.device_type == DeviceType::AppleTV
                    && device.service_type == REMOTEPAIRING_SERVICE
            })
            .filter_map(|device| {
                let ip = device.ip_address.as_deref()?.parse().ok()?;
                let port = device.port?;
                let same_ip = known_ip == Some(ip);
                let same_identity = pairing_identity.as_deref().is_some_and(|identity| {
                    device.hostname.eq_ignore_ascii_case(identity)
                        || device.name.eq_ignore_ascii_case(identity)
                });
                let same_name = !self.name.is_empty()
                    && device.name.eq_ignore_ascii_case(&self.name);
                if !(same_ip || same_identity || same_name) {
                    return None;
                }
                Some(((same_ip, same_identity, same_name), (ip, port)))
            })
            .max_by_key(|(matches, _)| *matches)
            .map(|(_, address)| address);

        if let Some(address) = candidate {
            self.reconnect_address = Some(address);
            log::info!(
                "tvOS pairing: using verified reconnect service at {}:{}",
                address.0,
                address.1
            );
            return Ok(());
        }

        Err(Error::Other(
            "Apple TV pairing succeeded, but its verified _remotepairing._tcp service was not found; scan again and retry"
                .to_string(),
        ))
    }

    pub async fn establish_tvos_tunnel(
        &self,
        cache_dir: PathBuf,
    ) -> Result<(AdapterHandle, RsdHandshake), Error> {
        self.core_device_transport(cache_dir)?.connect().await
    }

    pub fn has_cached_pairing_file(&self, cache_dir: &Path) -> bool {
        self.pairing_cache_path(cache_dir)
            .map(|path| path.exists())
            .unwrap_or(false)
    }

    pub fn has_pairing_source(&self, cache_dir: &Path) -> bool {
        if self.has_cached_pairing_file(cache_dir) {
            return true;
        }

        #[cfg(target_os = "macos")]
        {
            return self.has_native_tvos_pairing();
        }

        #[cfg(not(target_os = "macos"))]
        false
    }

    pub async fn forget_tvos_pairing(&self, cache_dir: PathBuf) -> Result<(), Error> {
        let path = self.pairing_cache_path(&cache_dir)?;

        #[cfg(target_os = "macos")]
        if self.has_native_tvos_pairing() {
            let selector = if crate::is_valid_device_udid(&self.udid) {
                self.udid.clone()
            } else if let Some(identity) = self
                .pairing_identity
                .as_deref()
                .filter(|identity| !identity.is_empty())
            {
                identity.to_string()
            } else {
                self.name.clone()
            };
            let output = std::process::Command::new("xcrun")
                .args([
                    "devicectl",
                    "manage",
                    "unpair",
                    "--device",
                    selector.as_str(),
                    "--timeout",
                    "45",
                ])
                .output()
                .map_err(|error| {
                    Error::Other(format!("Could not run xcrun devicectl unpair: {error}"))
                })?;
            if !output.status.success() {
                let details = String::from_utf8_lossy(&output.stderr)
                    .trim()
                    .to_string();
                let details = if details.is_empty() {
                    String::from_utf8_lossy(&output.stdout).trim().to_string()
                } else {
                    details
                };
                return Err(Error::Other(format!(
                    "Could not remove the native Apple TV pairing: {}",
                    if details.is_empty() {
                        output.status.to_string()
                    } else {
                        details
                    }
                )));
            }
        }

        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn fetch_tvos_info(&self, cache_dir: PathBuf) -> Result<TvosDeviceInfo, Error> {
        let (_adapter, handshake) = self.establish_tvos_tunnel(cache_dir).await?;
        Ok(TvosDeviceInfo::from_rsd_properties(&handshake.properties))
    }

    #[cfg(target_os = "macos")]
    fn has_native_tvos_pairing(&self) -> bool {
        let expected_name = self.name.to_ascii_lowercase();
        let expected_product_type = self
            .product_type
            .as_deref()
            .map(str::to_ascii_lowercase);

        for host_path in external_pairing_paths() {
            let Some(peers_path) = host_path.parent().map(|path| path.join("peers")) else {
                continue;
            };
            let Ok(entries) = std::fs::read_dir(peers_path) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("plist") {
                    continue;
                }
                let Ok(bytes) = std::fs::read(path) else {
                    continue;
                };
                let Ok(peer) = plist::from_bytes::<plist::Dictionary>(&bytes) else {
                    continue;
                };
                let model = peer
                    .get("model")
                    .and_then(Value::as_string)
                    .map(str::to_ascii_lowercase);
                let name = peer
                    .get("name")
                    .and_then(Value::as_string)
                    .map(str::to_ascii_lowercase);
                let model_matches = model.as_deref().is_some_and(|model| {
                    model.starts_with("appletv")
                        && expected_product_type
                            .as_deref()
                            .is_none_or(|expected| expected == model)
                });
                let name_matches = name.as_deref() == Some(expected_name.as_str());
                if model_matches && name_matches {
                    return true;
                }
            }
        }

        false
    }

    pub fn apply_tvos_info(&mut self, info: &TvosDeviceInfo) {
        if self.pairing_identity.is_none() {
            return;
        }
        if let Some(name) = info.name.as_deref().filter(|value| !value.is_empty()) {
            self.name = name.to_string();
        }
        if let Some(udid) = info.udid.as_deref() {
            if crate::is_valid_device_udid(udid) {
                self.udid = udid.to_string();
            }
        }
        if info.product_type.is_some() {
            self.product_type = info.product_type.clone();
        }
        if info.device_class.is_some() {
            self.device_class = info.device_class.clone();
        }
        if info.os_version.is_some() {
            self.os_version = info.os_version.clone();
        }
        if info.serial_number.is_some() {
            self.serial_number = info.serial_number.clone();
        }
        if info.udid.as_deref().is_some_and(crate::is_valid_device_udid) {
            self.core_device_authenticated = true;
        }
    }

    pub async fn install_app<F, Fut>(
        &self,
        app_path: &PathBuf,
        progress_callback: F,
    ) -> Result<(), Error>
    where
        F: FnMut(i32) -> Fut + Send + Clone + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let callback = move |(progress, _): (u64, ())| {
            let mut cb = progress_callback.clone();
            async move {
                cb(progress as i32).await;
            }
        };
        let state = ();

        if self.usbmuxd_device.is_some() {
            let provider = self.usbmuxd_device.clone().unwrap().to_provider(
                UsbmuxdAddr::from_env_var().unwrap_or_default(),
                INSTALLATION_LABEL,
            );

            installation::install_package_with_callback(&provider, app_path, None, callback, state)
                .await?;
        } else if self.is_network() {
            let cache_dir = self.pairing_cache_dir.clone().ok_or_else(|| {
                Error::Other(
                    "Network Apple TV has no pairing_cache_dir configured on this Device; \
                     install_app has nowhere to look for its pairing file"
                        .to_string(),
                )
            })?;

            let transport = self.core_device_transport(cache_dir)?;
            let (mut adapter, mut handshake) = transport.connect().await?;

            installation::install_package_with_callback_rsd(
                &mut adapter,
                &mut handshake,
                app_path,
                None,
                callback,
                state,
            )
            .await?;
        } else {
            return Err(Error::Other(
                "Device has no USB connection and no network address; cannot install".to_string(),
            ));
        }

        Ok(())
    }
}

fn pairing_cache_path_for(
    pairing_identity: Option<&str>,
    udid: &str,
    cache_dir: &Path,
) -> Result<PathBuf, Error> {
    let key = pairing_identity.unwrap_or(udid);

    if key.is_empty() {
        return Err(Error::Other(
            "Device has neither a pairing identity nor a UDID; cannot locate its pairing \
             file cache"
                .to_string(),
        ));
    }
    if key.contains('/')
        || key.contains('\\')
        || key.contains(':')
        || key.chars().all(|c| c == '.')
    {
        return Err(Error::Other(format!(
            "Pairing identity {key:?} is not a valid cache key"
        )));
    }

    Ok(cache_dir.join(format!("plume_{key}.plist")))
}

async fn try_import_external_pairing_at(
    address: Option<(std::net::IpAddr, u16)>,
    cache_dir: &Path,
    cache_path: &Path,
) -> Result<Option<RpPairingFile>, Error> {
    let Some((ip, port)) = address else {
        return Ok(None);
    };
    let address = std::net::SocketAddr::new(ip, port);

    for (source, mut pairing_file) in external_pairing_candidates() {
        let stream = match tokio::net::TcpStream::connect(address).await {
            Ok(stream) => stream,
            Err(error) => {
                log::debug!(
                    "Could not connect to Apple TV while trying external pairing record {}: {error}",
                    source
                );
                continue;
            }
        };
        let sending_host = pairing_file.identifier.clone();
        let mut client = RemotePairingClient::new(
            RpPairingSocket::new(stream),
            &sending_host,
            &mut pairing_file,
        );
        let valid = client.attempt_pair_verify().await.is_ok()
            && client.validate_pairing().await.is_ok();
        drop(client);

        if valid {
            write_pairing_file(&pairing_file, cache_dir, cache_path).await?;
            log::info!(
                "Imported an existing Apple TV pairing record from {}",
                source
            );
            return Ok(Some(pairing_file));
        }
    }

    Ok(None)
}

enum CoreDeviceTunnelAttemptError {
    Pairing(Error),
    Tunnel(Error),
}

fn tvos_create_listener_request(encryption_key: &[u8]) -> Value {
    let mut listener = plist::Dictionary::new();
    listener.insert(
        "key".to_string(),
        Value::String(STANDARD.encode(encryption_key)),
    );

    let mut peer_connection = plist::Dictionary::new();
    peer_connection.insert(
        "owningPID".to_string(),
        Value::Integer((std::process::id() as i64).into()),
    );
    peer_connection.insert(
        "owningProcessName".to_string(),
        Value::String("CoreDeviceService".to_string()),
    );
    listener.insert(
        "peerConnectionsInfo".to_string(),
        Value::Array(vec![Value::Dictionary(peer_connection)]),
    );
    listener.insert(
        "transportProtocolType".to_string(),
        Value::String("tcp".to_string()),
    );

    let mut operation = plist::Dictionary::new();
    operation.insert("createListener".to_string(), Value::Dictionary(listener));

    let mut request_body = plist::Dictionary::new();
    request_body.insert("_0".to_string(), Value::Dictionary(operation));

    let mut request = plist::Dictionary::new();
    request.insert("request".to_string(), Value::Dictionary(request_body));
    Value::Dictionary(request)
}

async fn create_tvos_tcp_listener<R: RpPairingSocketProvider>(
    rpc: &mut RemotePairingClient<'_, R>,
) -> Result<u16, Error> {
    let request = tvos_create_listener_request(rpc.encryption_key());
    let response = rpc.send_receive_encrypted_request(request).await?;
    log::debug!("tvOS createListener response: {response:#?}");

    let port = response
        .as_dictionary()
        .and_then(|value| value.get("createListener"))
        .and_then(Value::as_dictionary)
        .and_then(|value| value.get("port"))
        .and_then(Value::as_unsigned_integer)
        .filter(|port| *port <= u16::MAX as u64)
        .ok_or_else(|| Error::Other("missing port in createListener response".to_string()))?;

    Ok(port as u16)
}

async fn establish_core_device_tunnel(
    pairing_address: Option<(std::net::IpAddr, u16)>,
    reconnect_address: Option<(std::net::IpAddr, u16)>,
    pairing_identity: Option<&str>,
    udid: &str,
    cache_dir: &Path,
) -> Result<(AdapterHandle, RsdHandshake), Error> {
    let (ip, port) = reconnect_address.ok_or_else(|| {
        if pairing_address.is_some() {
            Error::Other(
                "Apple TV has only its manual-pairing service; discover its verified _remotepairing._tcp service before opening a tunnel"
                    .to_string(),
            )
        } else {
            Error::Other("Device has no network address".to_string())
        }
    })?;

    let connect_addr = std::net::SocketAddr::new(ip, port);
    let cache_path = pairing_cache_path_for(pairing_identity, udid, cache_dir)?;
    let (mut pairing_file, mut can_try_external) = if cache_path.exists() {
        (RpPairingFile::read_from_file(&cache_path).await?, true)
    } else {
        (
            try_import_external_pairing_at(Some((ip, port)), cache_dir, &cache_path)
                .await?
                .ok_or_else(|| {
                    Error::Other(
                        "No pairing record is cached for this Apple TV; pair before reconnecting"
                            .to_string(),
                    )
                })?,
            false,
        )
    };

    let tunnel = loop {
        let stream = tokio::net::TcpStream::connect(connect_addr).await.map_err(|e| {
            Error::Other(format!("Could not connect to Apple TV at {connect_addr}: {e}"))
        })?;
        let conn = RpPairingSocket::new(stream);
        let hostname = pairing_file.identifier.clone();

        let attempt: Result<_, CoreDeviceTunnelAttemptError> = async {
            let mut rpc = RemotePairingClient::new(conn, &hostname, &mut pairing_file);

            if let Err(e) = rpc.attempt_pair_verify().await {
                return Err(CoreDeviceTunnelAttemptError::Pairing(Error::Other(
                    format!("Pair-verify failed: {e}"),
                )));
            }

            if let Err(e) = rpc.validate_pairing().await {
                return Err(CoreDeviceTunnelAttemptError::Pairing(Error::Other(
                    format!(
                        "This Apple TV no longer recognizes this pairing (it may have been reset, \
                         forgotten, or lost pairing after a system update); pair with it again: {e}"
                    ),
                )));
            }

            let tunnel_port = create_tvos_tcp_listener(&mut rpc).await.map_err(|e| {
                CoreDeviceTunnelAttemptError::Tunnel(Error::Other(format!(
                    "Failed to create tunnel listener: {e}"
                )))
            })?;

            let tunnel_addr = std::net::SocketAddr::new(connect_addr.ip(), tunnel_port);
            let tunnel_stream = tokio::net::TcpStream::connect(tunnel_addr)
                .await
                .map_err(|e| {
                    CoreDeviceTunnelAttemptError::Tunnel(Error::Other(format!(
                        "TLS tunnel connect failed: {e}"
                    )))
                })?;

            connect_tls_psk_tunnel_native(Box::new(tunnel_stream), rpc.encryption_key())
                .await
                .map_err(|e| {
                    CoreDeviceTunnelAttemptError::Tunnel(Error::Other(format!(
                        "TLS-PSK tunnel handshake failed: {e}"
                    )))
                })
        }
        .await;

        match attempt {
            Ok(tunnel) => break tunnel,
            Err(CoreDeviceTunnelAttemptError::Pairing(error)) if can_try_external => {
                can_try_external = false;
                log::warn!(
                    "tvOS tunnel: cached pairing file at {} is stale ({error}); removing it",
                    cache_path.display()
                );
                let _ = tokio::fs::remove_file(&cache_path).await;

                if let Some(imported) =
                    try_import_external_pairing_at(Some((ip, port)), cache_dir, &cache_path)
                        .await?
                {
                    pairing_file = imported;
                    continue;
                }

                return Err(error);
            }
            Err(CoreDeviceTunnelAttemptError::Pairing(error))
            | Err(CoreDeviceTunnelAttemptError::Tunnel(error)) => return Err(error),
        }
    };

    let client_ip: std::net::IpAddr = tunnel
        .info
        .client_address
        .parse()
        .map_err(|e| Error::Other(format!("Invalid tunnel client address: {e}")))?;
    let server_ip: std::net::IpAddr = tunnel
        .info
        .server_address
        .parse()
        .map_err(|e| Error::Other(format!("Invalid tunnel server address: {e}")))?;
    let rsd_port = tunnel.info.server_rsd_port;
    let mtu = tunnel.info.mtu as usize;
    let mss = mtu.saturating_sub(60);
    log::info!("tvOS tunnel: negotiated MTU {mtu}, using MSS {mss}");

    let raw = tunnel.into_inner();
    let mut adapter = Adapter::new(Box::new(raw), client_ip, server_ip);
    adapter.set_mss(mss);
    let mut adapter_handle = adapter.to_async_handle();

    let rsd_stream = adapter_handle
        .connect(rsd_port)
        .await
        .map_err(|e| Error::Other(format!("RSD connection failed: {e}")))?;
    let handshake = RsdHandshake::new(rsd_stream)
        .await
        .map_err(|e| Error::Other(format!("RSD handshake failed: {e}")))?;

    Ok((adapter_handle, handshake))
}

async fn write_pairing_file(
    pairing_file: &RpPairingFile,
    cache_dir: &Path,
    cache_path: &Path,
) -> Result<(), Error> {
    tokio::fs::create_dir_all(cache_dir).await?;

    #[cfg(unix)]
    tokio::fs::set_permissions(
        cache_dir,
        std::fs::Permissions::from_mode(0o700),
    )
    .await?;

    let temporary_path = cache_path.with_extension("plist.tmp");
    tokio::fs::write(&temporary_path, pairing_file.to_bytes()).await?;

    #[cfg(unix)]
    tokio::fs::set_permissions(
        &temporary_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .await?;

    tokio::fs::rename(&temporary_path, cache_path).await?;

    #[cfg(unix)]
    tokio::fs::set_permissions(cache_path, std::fs::Permissions::from_mode(0o600)).await?;

    Ok(())
}

fn external_pairing_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut paths = Vec::new();

        let native_dir = Path::new("/var/db/lockdown/RemotePairing");
        if let Ok(entries) = std::fs::read_dir(native_dir) {
            for entry in entries.flatten() {
                let path = entry.path().join("selfIdentity.plist");
                if path.is_file() {
                    paths.push(path);
                }
            }
        }

        paths.sort();
        paths.dedup();
        paths
    }

    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

fn external_pairing_candidates() -> Vec<(String, RpPairingFile)> {
    let mut candidates = Vec::new();

    for path in external_pairing_paths() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };

        let peer_paths = path
            .parent()
            .map(|parent| parent.join("peers"))
            .and_then(|directory| std::fs::read_dir(directory).ok())
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("plist"))
            .collect::<Vec<_>>();
        let peer_bytes = peer_paths
            .iter()
            .filter_map(|peer_path| std::fs::read(peer_path).ok())
            .collect::<Vec<_>>();
        let peer_refs = peer_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>();

        if let Ok(native_candidates) = native_pairing_candidates_from_bytes(&bytes, &peer_refs) {
            for (index, candidate) in native_candidates.into_iter().enumerate() {
                let source = if index == 0 {
                    path.display().to_string()
                } else {
                    peer_paths
                        .get(index - 1)
                        .map(|peer_path| peer_path.display().to_string())
                        .unwrap_or_else(|| path.display().to_string())
                };
                candidates.push((source, candidate));
            }
        }
    }

    candidates
}

fn native_pairing_candidates_from_bytes(
    host_bytes: &[u8],
    peer_bytes: &[&[u8]],
) -> Result<Vec<RpPairingFile>, Error> {
    let mut host = external_pairing_file_from_bytes(host_bytes)?;
    host.alt_irk = None;

    let mut candidates = vec![host.clone()];
    for bytes in peer_bytes {
        let Ok(peer) = plist::from_bytes::<plist::Dictionary>(bytes) else {
            continue;
        };
        let Some(irk) = ["irk", "altIRK", "alt_irk"].iter().find_map(|key| {
            peer.get(*key)
                .and_then(plist::Value::as_data)
                .filter(|data| data.len() == 16)
                .map(|data| data.to_vec())
        }) else {
            continue;
        };

        let mut candidate = host.clone();
        candidate.alt_irk = Some(irk);
        candidates.push(candidate);
    }

    Ok(candidates)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairingAction {
    FirstPairing,
    Reconnect,
}

fn pairing_action(
    has_cached_pairing: bool,
    has_pairing_service: bool,
    has_reconnect_service: bool,
) -> Result<PairingAction, String> {
    if has_cached_pairing && (has_reconnect_service || has_pairing_service) {
        Ok(PairingAction::Reconnect)
    } else if !has_cached_pairing && has_pairing_service {
        Ok(PairingAction::FirstPairing)
    } else if has_cached_pairing {
        Err("Apple TV pairing record is stale and no pairing service is currently advertised".to_string())
    } else {
        Err(
            "Apple TV is not advertising its manual-pairing service; open Settings > Remotes and Devices > Remote App and Devices and wait for \"Waiting to Pair...\", then scan again".to_string(),
        )
    }
}

#[cfg(not(target_os = "macos"))]
fn pairing_failure_to_error(failure: PairingFailure) -> Error {
    match failure {
        PairingFailure::Cancelled => Error::Other("Apple TV pairing was cancelled".to_string()),
        PairingFailure::InvalidPin => {
            Error::Other("Apple TV pairing PIN must contain exactly six digits".to_string())
        }
        PairingFailure::WrongPin => Error::Other("Apple TV rejected the pairing PIN".to_string()),
        PairingFailure::StaleRecord => Error::Other(
            "This Apple TV pairing record is stale; open the Apple TV pairing screen and try again"
                .to_string(),
        ),
        PairingFailure::ServiceDisappeared => Error::Other(
            "Apple TV pairing service disappeared; scan again while the pairing screen is open"
                .to_string(),
        ),
        PairingFailure::Protocol(message) => {
            Error::Other(format!("RPPairing handshake failed: {message}"))
        }
    }
}

fn local_remote_pairing_hostname() -> Option<String> {
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .filter(|hostname| !hostname.trim().is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|hostname| hostname.trim().to_string())
                .filter(|hostname| !hostname.is_empty())
        })?;

    Some(hostname)
}

#[cfg(not(target_os = "macos"))]
fn local_remote_pairing_host() -> Option<String> {
    std::process::Command::new("scutil")
        .args(["--get", "ComputerName"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|hostname| hostname.trim().to_string())
        .filter(|hostname| !hostname.is_empty())
        .or_else(local_remote_pairing_hostname)
}

fn local_remote_pairing_identifier() -> Option<String> {
    let hostname = local_remote_pairing_hostname()?;
    Some(
        uuid::Uuid::new_v3(&uuid::Uuid::NAMESPACE_DNS, hostname.as_bytes())
            .to_string()
            .to_uppercase(),
    )
}

fn external_pairing_file_from_bytes(bytes: &[u8]) -> Result<RpPairingFile, Error> {
    let source: plist::Dictionary = plist::from_bytes(bytes)?;
    let data_field = |names: &[&str]| {
        names.iter().find_map(|name| {
            source
                .get(*name)
                .and_then(plist::Value::as_data)
                .map(|data| data.to_vec())
        })
    };
    let string_field = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| source.get(*name).and_then(plist::Value::as_string))
            .map(str::to_string)
    };

    let public_key = data_field(&["public_key", "publicKey"])
        .filter(|key| key.len() == 32)
        .ok_or_else(|| Error::Other("External pairing record has no valid public key".to_string()))?;
    let private_key = data_field(&["private_key", "privateKey"])
        .filter(|key| key.len() == 32)
        .ok_or_else(|| Error::Other("External pairing record has no valid private key".to_string()))?;
    let identifier = string_field(&["identifier", "host_identifier"])
        .or_else(local_remote_pairing_identifier)
        .ok_or_else(|| Error::Other("External pairing record has no host identifier".to_string()))?;

    let mut normalized = plist::Dictionary::new();
    normalized.insert("public_key".to_string(), plist::Value::Data(public_key));
    normalized.insert("private_key".to_string(), plist::Value::Data(private_key));
    normalized.insert(
        "identifier".to_string(),
        plist::Value::String(identifier),
    );
    if let Some(irk) = data_field(&["alt_irk", "irk", "host_alt_irk"]) {
        if irk.len() == 16 {
            normalized.insert("alt_irk".to_string(), plist::Value::Data(irk));
        }
    }

    let mut normalized_bytes = Vec::new();
    plist::to_writer_xml(&mut normalized_bytes, &normalized)?;
    Ok(RpPairingFile::from_bytes(&normalized_bytes)?)
}

fn get_app_name_from_info(info: &Value) -> Option<String> {
    let dict = info.as_dictionary()?;
    dict.get("CFBundleDisplayName")
        .and_then(|value| value.as_string())
        .or_else(|| dict.get("CFBundleName").and_then(|value| value.as_string()))
        .or_else(|| {
            dict.get("CFBundleExecutable")
                .and_then(|value| value.as_string())
        })
        .map(|value| value.to_string())
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let conn = if self.pairing_address.is_some() || self.reconnect_address.is_some() {
            "WiFi"
        } else {
            match &self.usbmuxd_device {
                Some(device) => match &device.connection_type {
                    Connection::Usb => "USB",
                    Connection::Network(_) => "WiFi",
                    Connection::Unknown(_) => "Unknown",
                },
                None => "LOCAL",
            }
        };
        let identity = if crate::is_valid_device_udid(&self.udid) {
            format!(" [{}…{}]", &self.udid[..8], &self.udid[self.udid.len() - 4..])
        } else if self.is_network() {
            " [unpaired]".to_string()
        } else {
            String::new()
        };
        let platform = if self.is_tvos() { " (tvOS)" } else { "" };
        write!(f, "[{conn}] {}{platform}{identity}", self.name)
    }
}

pub async fn get_device_for_id(device_id: &str) -> Result<Device, Error> {
    let mut usbmuxd = UsbmuxdConnection::default().await?;
    let usbmuxd_device = usbmuxd
        .get_devices()
        .await?
        .into_iter()
        .find(|d| {
            d.device_id.to_string() == device_id || d.udid.eq_ignore_ascii_case(device_id)
        })
        .ok_or_else(|| Error::Other(format!("Device ID {device_id} not found")))?;

    Ok(Device::new(usbmuxd_device).await)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub async fn install_app_mac(app_path: &PathBuf) -> Result<(), Error> {
    use crate::copy_dir_recursively;
    use std::env;
    use tokio::fs;
    use uuid::Uuid;

    let stage_dir = env::temp_dir().join(format!(
        "plume_mac_stage_{}",
        Uuid::new_v4().to_string().to_uppercase()
    ));
    let app_name = app_path
        .file_name()
        .ok_or(Error::Other("Invalid app path".to_string()))?;

    // iOS Apps on macOS need to be wrapped in a special structure, more specifically
    // ```
    // LiveContainer.app
    // ├── WrappedBundle -> Wrapper/LiveContainer.app
    // └── Wrapper
    //     └── LiveContainer.app
    // ```
    // Then install to /Applications/...

    let outer_app_dir = stage_dir.join(app_name);
    let wrapper_dir = outer_app_dir.join("Wrapper");

    fs::create_dir_all(&wrapper_dir).await?;

    copy_dir_recursively(app_path, &wrapper_dir.join(app_name)).await?;

    let wrapped_bundle_path = outer_app_dir.join("WrappedBundle");
    fs::symlink(
        PathBuf::from("Wrapper").join(app_name),
        &wrapped_bundle_path,
    )
    .await?;

    let applications_dir = PathBuf::from("/Applications/iOS");
    fs::create_dir_all(&applications_dir).await?;

    let applications_dir = applications_dir.join(app_name);

    fs::remove_dir_all(&applications_dir).await.ok();

    fs::rename(&outer_app_dir, &applications_dir)
        .await
        .map_err(|_| Error::BundleFailedToCopy(applications_dir.to_string_lossy().into_owned()))?;

    Ok(())
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub async fn install_app_mac(_app_path: &PathBuf) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn real_rsd_properties() -> HashMap<String, plist::Value> {
        let mut props = HashMap::new();
        props.insert(
            "UniqueDeviceID".to_string(),
            plist::Value::String("00008110-001E60481AD9401E".to_string()),
        );
        props.insert(
            "ProductType".to_string(),
            plist::Value::String("AppleTV14,1".to_string()),
        );
        props.insert(
            "DeviceClass".to_string(),
            plist::Value::String("AppleTV".to_string()),
        );
        props.insert(
            "OSVersion".to_string(),
            plist::Value::String("26.5".to_string()),
        );
        props.insert(
            "HumanReadableProductVersionString".to_string(),
            plist::Value::String("26.5".to_string()),
        );
        props.insert(
            "SerialNumber".to_string(),
            plist::Value::String("C6FCY44V73".to_string()),
        );
        props.insert(
            "HWModel".to_string(),
            plist::Value::String("J255AP".to_string()),
        );
        props.insert(
            "ProductName".to_string(),
            plist::Value::String("Apple TVOS".to_string()),
        );
        props.insert(
            "BuildVersion".to_string(),
            plist::Value::String("23L471".to_string()),
        );
        props
    }

    #[test]
    fn from_rsd_properties_reads_real_device_fields() {
        let info = TvosDeviceInfo::from_rsd_properties(&real_rsd_properties());
        assert_eq!(info.udid.as_deref(), Some("00008110-001E60481AD9401E"));
        assert_eq!(info.product_type.as_deref(), Some("AppleTV14,1"));
        assert_eq!(info.device_class.as_deref(), Some("AppleTV"));
        assert_eq!(info.os_version.as_deref(), Some("26.5"));
        assert_eq!(info.serial_number.as_deref(), Some("C6FCY44V73"));
    }

    #[test]
    fn from_rsd_properties_empty_map_yields_default() {
        let info = TvosDeviceInfo::from_rsd_properties(&HashMap::new());
        assert_eq!(info, TvosDeviceInfo::default());
    }

    #[test]
    fn from_rsd_properties_non_string_value_yields_none() {
        let mut props = HashMap::new();
        props.insert(
            "UniqueDeviceID".to_string(),
            plist::Value::Integer(12345.into()),
        );

        let info = TvosDeviceInfo::from_rsd_properties(&props);
        assert_eq!(info.udid, None);
    }

    #[test]
    fn from_rsd_properties_falls_back_to_human_readable_version() {
        let mut props = HashMap::new();
        props.insert(
            "HumanReadableProductVersionString".to_string(),
            plist::Value::String("17.1".to_string()),
        );

        let info = TvosDeviceInfo::from_rsd_properties(&props);
        assert_eq!(info.os_version.as_deref(), Some("17.1"));
    }

    #[test]
    fn from_rsd_properties_prefers_os_version_over_human_readable_when_both_present() {
        let mut props = HashMap::new();
        props.insert(
            "OSVersion".to_string(),
            plist::Value::String("26.5".to_string()),
        );
        props.insert(
            "HumanReadableProductVersionString".to_string(),
            plist::Value::String("26.5 (23L471)".to_string()),
        );

        let info = TvosDeviceInfo::from_rsd_properties(&props);
        assert_eq!(info.os_version.as_deref(), Some("26.5"));
    }

    #[test]
    fn display_keeps_tvos_platform_out_of_connection_brackets() {
        let mut device = Device::new_tvos(
            "Apple TV".to_string(),
            "Apple-TV".to_string(),
            "192.0.2.10".parse().unwrap(),
            None,
            Some(49152),
            std::env::temp_dir(),
        );
        device.udid = "00008110-000C25540CD1801E".to_string();

        assert_eq!(
            device.to_string(),
            "[WiFi] Apple TV (tvOS) [00008110…801E]"
        );
    }

    #[test]
    fn new_tvos_leaves_udid_empty_and_sets_pairing_identity() {
        let d = Device::new_tvos(
            "Apple TV".to_string(),
            "Apple-TV".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Some(1234),
            None,
            std::env::temp_dir(),
        );
        assert!(d.udid.is_empty());
        assert_eq!(d.pairing_identity.as_deref(), Some("Apple-TV"));
    }

    #[test]
    fn new_tvos_stores_pairing_cache_dir() {
        let cache_dir = std::env::temp_dir().join("plume_test_new_tvos_cache_dir");
        let d = Device::new_tvos(
            "Apple TV".to_string(),
            "Apple-TV".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Some(1234),
            None,
            cache_dir.clone(),
        );
        assert_eq!(d.pairing_cache_dir, Some(cache_dir));
    }

    fn stub_device() -> Device {
        Device {
            name: "Test Device".to_string(),
            udid: "00008110-000C25540CD1801E".to_string(),
            product_type: None,
            device_class: None,
            os_version: None,
            serial_number: None,
            device_id: 0,
            usbmuxd_device: None,
            is_mac: false,
            pairing_address: None,
            reconnect_address: None,
            pairing_identity: None,
            pairing_cache_dir: None,
            core_device_authenticated: false,
        }
    }

    fn stub_tvos_device() -> Device {
        let mut d = stub_device();
        d.pairing_identity = Some("stable-key".to_string());
        d
    }

    #[test]
    fn apply_tvos_info_none_udid_leaves_existing_udid_unchanged() {
        let mut device = stub_tvos_device();
        let info = TvosDeviceInfo {
            udid: None,
            ..Default::default()
        };
        device.apply_tvos_info(&info);
        assert_eq!(device.udid, "00008110-000C25540CD1801E");
    }

    #[test]
    fn apply_tvos_info_some_udid_overwrites_existing_udid() {
        let mut device = stub_tvos_device();
        let info = TvosDeviceInfo {
            udid: Some("00008110-000C25540CD1801F".to_string()),
            ..Default::default()
        };
        device.apply_tvos_info(&info);
        assert_eq!(device.udid, "00008110-000C25540CD1801F");
    }

    #[test]
    fn apply_tvos_info_empty_udid_leaves_existing_udid_unchanged() {
        let mut device = stub_tvos_device();
        let info = TvosDeviceInfo {
            udid: Some(String::new()),
            ..Default::default()
        };
        device.apply_tvos_info(&info);
        assert_eq!(device.udid, "00008110-000C25540CD1801E");
    }

    #[test]
    fn apply_tvos_info_no_op_when_device_has_no_pairing_identity() {
        let mut device = stub_device();
        let info = TvosDeviceInfo {
            udid: Some("00008110-000C25540CD1801F".to_string()),
            ..Default::default()
        };
        device.apply_tvos_info(&info);
        assert_eq!(device.udid, "00008110-000C25540CD1801E");
    }

    #[test]
    fn is_tvos_true_for_network_paired_device() {
        let device = stub_tvos_device();
        assert!(device.is_tvos());
    }

    #[test]
    fn is_tvos_false_for_usb_device() {
        let device = stub_device();
        assert!(!device.is_tvos());
    }

    #[test]
    fn new_tvos_device_reports_is_tvos() {
        let d = Device::new_tvos(
            "Apple TV".to_string(),
            "Apple-TV".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Some(1234),
            None,
            std::env::temp_dir(),
        );
        assert!(d.is_tvos());
        assert_eq!(d.transport(), DeviceTransport::RemotePairing);
    }

    #[test]
    fn authenticated_rsd_metadata_promotes_remote_pairing_to_core_device() {
        let mut device = Device::new_tvos(
            "Apple TV".to_string(),
            "Apple-TV".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Some(1234),
            Some(1235),
            std::env::temp_dir(),
        );

        device.apply_tvos_info(&TvosDeviceInfo {
            udid: Some("00008110-000C25540CD1801E".to_string()),
            ..Default::default()
        });

        assert_eq!(device.transport(), DeviceTransport::CoreDevice);
        assert!(device.is_network());
    }

    #[test]
    fn core_device_transport_exposes_authenticated_device_kind() {
        let mut device = Device::new_tvos(
            "Apple TV".to_string(),
            "Apple-TV".to_string(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            Some(1234),
            Some(1235),
            std::env::temp_dir(),
        );
        device.apply_tvos_info(&TvosDeviceInfo {
            udid: Some("00008110-000C25540CD1801E".to_string()),
            ..Default::default()
        });

        let transport = device
            .core_device_transport(std::env::temp_dir())
            .unwrap();

        assert_eq!(transport.kind(), DeviceTransport::CoreDevice);
    }

    #[test]
    fn transport_identifies_usb_and_unavailable_devices() {
        let mut usb = stub_device();
        usb.usbmuxd_device = Some(UsbmuxdDevice {
            connection_type: Connection::Usb,
            udid: usb.udid.clone(),
            device_id: usb.device_id,
        });
        assert_eq!(usb.transport(), DeviceTransport::Usbmuxd);

        let mut unavailable = usb;
        unavailable.usbmuxd_device = None;
        assert_eq!(unavailable.transport(), DeviceTransport::Unavailable);
    }

    #[test]
    fn pairing_cache_path_prefers_pairing_identity_over_udid() {
        let device = stub_tvos_device();
        let cache_dir = Path::new("/cache");
        assert_eq!(
            device.pairing_cache_path(cache_dir).unwrap(),
            cache_dir.join("plume_stable-key.plist")
        );
    }

    #[test]
    fn pairing_cache_path_falls_back_to_udid_when_no_pairing_identity() {
        let device = stub_device();
        let cache_dir = Path::new("/cache");
        assert_eq!(
            device.pairing_cache_path(cache_dir).unwrap(),
            cache_dir.join("plume_00008110-000C25540CD1801E.plist")
        );
    }

    #[test]
    fn pairing_cache_path_rejects_empty_key() {
        let mut device = stub_device();
        device.udid = String::new();
        let cache_dir = Path::new("/cache");
        assert!(device.pairing_cache_path(cache_dir).is_err());
    }

    #[test]
    fn pairing_cache_path_rejects_dots_only_key() {
        let mut device = stub_device();
        device.pairing_identity = Some("..".to_string());
        let cache_dir = Path::new("/cache");
        assert!(device.pairing_cache_path(cache_dir).is_err());
    }

    #[test]
    fn pairing_cache_path_rejects_key_with_path_separator() {
        let mut device = stub_device();
        device.pairing_identity = Some("../evil".to_string());
        let cache_dir = Path::new("/cache");
        assert!(device.pairing_cache_path(cache_dir).is_err());
    }

    fn unique_temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "plume_test_{tag}_{}",
            uuid::Uuid::new_v4().simple()
        ))
    }

    #[test]
    fn has_cached_pairing_file_reports_presence_and_absence() {
        let cache_dir = unique_temp_dir("has_cached_pairing_file");
        std::fs::create_dir_all(&cache_dir).expect("create scratch cache dir");

        let mut device = stub_tvos_device();
        device.pairing_identity = Some("has-cache-test".to_string());

        assert!(!device.has_cached_pairing_file(&cache_dir));

        let cache_path = device.pairing_cache_path(&cache_dir).unwrap();
        std::fs::write(&cache_path, b"stub").unwrap();

        assert!(device.has_cached_pairing_file(&cache_dir));

        std::fs::remove_dir_all(&cache_dir).ok();
    }

    #[test]
    fn external_pairing_record_import_supports_native_shape() {
        let source = RpPairingFile::generate("external-record-test");
        let mut native = plist::Dictionary::new();
        native.insert(
            "publicKey".to_string(),
            plist::Value::Data(source.public_key_bytes()),
        );
        native.insert(
            "privateKey".to_string(),
            plist::Value::Data(source.private_key_bytes()),
        );
        native.insert(
            "identifier".to_string(),
            plist::Value::String(source.identifier.clone()),
        );
        native.insert("irk".to_string(), plist::Value::Data(vec![7; 16]));

        let mut native_bytes = Vec::new();
        plist::to_writer_xml(&mut native_bytes, &native).unwrap();
        let imported_native = external_pairing_file_from_bytes(&native_bytes).unwrap();
        assert_eq!(imported_native.identifier, source.identifier);
        assert_eq!(imported_native.public_key_bytes(), source.public_key_bytes());
        assert_eq!(imported_native.alt_irk(), Some(&[7; 16][..]));

    }

    #[test]
    fn native_pairing_candidates_combine_xcode_host_identity_with_each_peer() {
        let source = RpPairingFile::generate("native-record-test");
        let mut host = plist::Dictionary::new();
        host.insert(
            "publicKey".to_string(),
            plist::Value::Data(source.public_key_bytes()),
        );
        host.insert(
            "privateKey".to_string(),
            plist::Value::Data(source.private_key_bytes()),
        );
        host.insert(
            "identifier".to_string(),
            plist::Value::String(source.identifier.clone()),
        );
        host.insert("irk".to_string(), plist::Value::Data(vec![1; 16]));

        let mut host_bytes = Vec::new();
        plist::to_writer_xml(&mut host_bytes, &host).unwrap();

        let mut peer_a = plist::Dictionary::new();
        peer_a.insert("irk".to_string(), plist::Value::Data(vec![2; 16]));
        let mut peer_b = plist::Dictionary::new();
        peer_b.insert("irk".to_string(), plist::Value::Data(vec![3; 16]));
        let mut peer_a_bytes = Vec::new();
        let mut peer_b_bytes = Vec::new();
        plist::to_writer_xml(&mut peer_a_bytes, &peer_a).unwrap();
        plist::to_writer_xml(&mut peer_b_bytes, &peer_b).unwrap();

        let candidates = native_pairing_candidates_from_bytes(
            &host_bytes,
            &[peer_a_bytes.as_slice(), peer_b_bytes.as_slice()],
        )
        .unwrap();

        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].alt_irk(), None);
        assert_eq!(candidates[1].alt_irk(), Some(&[2; 16][..]));
        assert_eq!(candidates[2].alt_irk(), Some(&[3; 16][..]));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.identifier == source.identifier));
    }

    #[test]
    fn pairing_action_covers_first_pairing_saved_reconnect_stale_and_disappeared_services() {
        assert_eq!(
            pairing_action(false, true, false),
            Ok(PairingAction::FirstPairing)
        );
        assert_eq!(
            pairing_action(true, false, true),
            Ok(PairingAction::Reconnect)
        );
        assert!(pairing_action(true, false, false)
            .unwrap_err()
            .contains("stale"));
        assert!(pairing_action(false, false, true)
            .unwrap_err()
            .contains("manual-pairing"));
    }

    #[test]
    fn tvos_listener_request_contains_coredevice_connection_metadata() {
        let request = tvos_create_listener_request(&[0, 1, 2, 255]);
        let listener = request
            .as_dictionary()
            .and_then(|value| value.get("request"))
            .and_then(Value::as_dictionary)
            .and_then(|value| value.get("_0"))
            .and_then(Value::as_dictionary)
            .and_then(|value| value.get("createListener"))
            .and_then(Value::as_dictionary)
            .expect("createListener request");

        assert_eq!(
            listener
                .get("key")
                .and_then(Value::as_string)
                .unwrap(),
            "AAEC/w=="
        );
        assert_eq!(
            listener
                .get("transportProtocolType")
                .and_then(Value::as_string),
            Some("tcp")
        );

        let peers = listener
            .get("peerConnectionsInfo")
            .and_then(Value::as_array)
            .expect("peer connection metadata");
        assert_eq!(peers.len(), 1);
        let peer = peers[0].as_dictionary().expect("peer connection");
        assert_eq!(
            peer.get("owningProcessName").and_then(Value::as_string),
            Some("CoreDeviceService")
        );
        assert_eq!(
            peer.get("owningPID").and_then(Value::as_unsigned_integer),
            Some(std::process::id() as u64)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pairing_cache_uses_restrictive_permissions() {
        let cache_dir = unique_temp_dir("pairing_permissions");
        let cache_path = cache_dir.join("plume_permissions.plist");
        let pairing_file = RpPairingFile::generate("permissions-test");

        write_pairing_file(&pairing_file, &cache_dir, &cache_path)
            .await
            .unwrap();

        assert_eq!(
            std::fs::metadata(&cache_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&cache_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        std::fs::remove_dir_all(&cache_dir).unwrap();
    }

    #[test]
    fn is_network_follows_the_transport_install_app_picks() {
        let mut device = stub_device();
        assert!(
            !device.is_network(),
            "a device with no transport at all is not a network device"
        );

        device.reconnect_address =
            Some((std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49151));
        assert!(device.is_network(), "a reconnect address makes it network");

        device.reconnect_address = None;
        device.pairing_address = Some((std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49152));
        assert!(device.is_network(), "a pairing address makes it network");

        let mut mac = stub_device();
        mac.is_mac = true;
        assert!(
            !mac.is_network(),
            "the local Mac is not reached over a tunnel"
        );
    }

    async fn noop_callback(_progress: i32) {}

    #[tokio::test]
    async fn install_app_with_no_transport_names_the_missing_transport() {
        let device = stub_device();

        let err = device
            .install_app(&PathBuf::from("nonexistent.ipa"), noop_callback)
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("no USB connection") && msg.contains("no network address"),
            "expected a message naming both missing transports, got: {msg}"
        );
    }

    #[tokio::test]
    async fn install_app_network_device_without_cache_dir_returns_distinct_error() {
        let mut device = stub_device();
        device.reconnect_address =
            Some((std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49151));
        assert!(device.pairing_cache_dir.is_none());

        let err = device
            .install_app(&PathBuf::from("nonexistent.ipa"), noop_callback)
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("pairing_cache_dir"),
            "expected the missing-cache-dir error, got: {msg}"
        );
        assert!(!msg.contains("no USB connection"));
        assert!(!msg.contains("No pairing file is cached"));
    }

    #[tokio::test]
    async fn install_app_network_device_with_no_pairing_file_errors_before_tunnel() {
        let cache_dir = unique_temp_dir("no_pairing_file");
        std::fs::create_dir_all(&cache_dir).expect("create scratch cache dir");

        let mut device = stub_device();
        device.reconnect_address =
            Some((std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49151));
        device.pairing_cache_dir = Some(cache_dir.clone());

        let err = device
            .install_app(&PathBuf::from("nonexistent.ipa"), noop_callback)
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("No pairing record is cached"),
            "expected the missing-pairing-file error, got: {msg}"
        );
        assert!(!msg.contains("pairing_cache_dir"));

        std::fs::remove_dir_all(&cache_dir).ok();
    }

    fn generated_identities(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("dev-{i}")).collect()
    }

    #[test]
    fn synthetic_device_id_is_deterministic() {
        for name in generated_identities(100_000) {
            assert_eq!(synthetic_device_id(&name), synthetic_device_id(&name));
        }
    }

    #[test]
    fn synthetic_device_id_never_zero_or_u32_max() {
        for name in generated_identities(100_000) {
            let id = synthetic_device_id(&name);
            assert_ne!(id, 0, "input {name:?} produced 0");
            assert_ne!(id, u32::MAX, "input {name:?} produced u32::MAX");
        }

        for input in ["", &"x".repeat(500)] {
            let id = synthetic_device_id(input);
            assert_ne!(id, 0, "input {input:?} produced 0");
            assert_ne!(id, u32::MAX, "input {input:?} produced u32::MAX");
        }
    }

    #[test]
    fn synthetic_device_id_top_bit_always_set() {
        let inputs = [
            "",
            "a",
            "Living-Room",
            "Bedroom",
            "Apple-TV",
            "Office",
            &"z".repeat(200),
        ];
        for input in inputs {
            let id = synthetic_device_id(input);
            assert_eq!(
                id & 0x8000_0000,
                0x8000_0000,
                "input {input:?} did not have the top bit set"
            );
        }
    }

    #[test]
    fn synthetic_device_id_distinct_for_realistic_names() {
        let names = ["Living-Room", "Bedroom", "Apple-TV", "Office"];
        let ids: Vec<u32> = names.iter().map(|n| synthetic_device_id(n)).collect();
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(
                    ids[i], ids[j],
                    "{:?} and {:?} produced the same id",
                    names[i], names[j]
                );
            }
        }
    }

    #[test]
    fn synthetic_device_id_known_value_regression() {
        assert_eq!(synthetic_device_id("Living-Room"), 0xe3eb1b88);
    }

    #[tokio::test]
    async fn establish_tvos_tunnel_takes_no_pin_argument() {
        let device = stub_device();
        let err = device
            .establish_tvos_tunnel(std::env::temp_dir())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no network address"));
    }
}
