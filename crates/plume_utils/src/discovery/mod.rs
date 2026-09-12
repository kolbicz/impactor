pub mod mdns;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use crate::{Device, synthetic_device_id};

pub const REMOTEPAIRING_MANUAL_PAIRING_SERVICE: &str = "_remotepairing-manual-pairing._tcp.local.";
pub const REMOTEPAIRING_SERVICE: &str = "_remotepairing._tcp.local.";
pub const APPLE_MOBDEV2_SERVICE: &str = "_apple-mobdev2._tcp.local.";
pub const APPLE_PAIRABLE_SERVICE: &str = "_apple-pairable._tcp.local.";
pub const COMPANION_LINK_SERVICE: &str = "_companion-link._tcp.local.";

pub const SERVICE_TYPES: [&str; 4] = [
    APPLE_MOBDEV2_SERVICE,
    APPLE_PAIRABLE_SERVICE,
    REMOTEPAIRING_SERVICE,
    REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
];

pub const METADATA_SERVICE_TYPES: [&str; 1] = [COMPANION_LINK_SERVICE];

pub const ALL_SCANNED_SERVICE_TYPES: [&str; 5] = [
    APPLE_MOBDEV2_SERVICE,
    APPLE_PAIRABLE_SERVICE,
    REMOTEPAIRING_SERVICE,
    REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
    COMPANION_LINK_SERVICE,
];

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceType {
    IPhone,
    IPad,
    AppleTV,
    AppleMac,
    Unknown,
}

impl DeviceType {
    pub fn from_device_class(device_class: &str) -> Self {
        match device_class {
            "iPhone" => DeviceType::IPhone,
            "iPad" => DeviceType::IPad,
            "AppleTV" => DeviceType::AppleTV,
            "Mac" => DeviceType::AppleMac,
            _ => DeviceType::Unknown,
        }
    }

    pub fn from_product_type(product_type: &str) -> Self {
        if product_type.starts_with("iPhone") {
            DeviceType::IPhone
        } else if product_type.starts_with("iPad") {
            DeviceType::IPad
        } else if product_type.starts_with("AppleTV") {
            DeviceType::AppleTV
        } else if product_type.starts_with("Mac") {
            DeviceType::AppleMac
        } else {
            DeviceType::Unknown
        }
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::IPhone => write!(f, "iPhone"),
            DeviceType::IPad => write!(f, "iPad"),
            DeviceType::AppleTV => write!(f, "Apple TV"),
            DeviceType::AppleMac => write!(f, "Mac"),
            DeviceType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionType {
    USB,
    WiFi,
}

impl std::fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionType::USB => write!(f, "USB"),
            ConnectionType::WiFi => write!(f, "WiFi"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub name: String,
    pub hostname: String,
    pub udid: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<u16>,
    pub device_type: DeviceType,
    pub connection_type: ConnectionType,
    pub is_paired: bool,
    pub product_type: Option<String>,
    pub os_version: Option<String>,
    pub service_type: String,
}


pub(crate) fn ends_with_ignore_case(s: &str, suffix: &str) -> bool {
    let (haystack, needle) = (s.as_bytes(), suffix.as_bytes());
    needle.len() <= haystack.len()
        && haystack[haystack.len() - needle.len()..].eq_ignore_ascii_case(needle)
}

pub(crate) fn parse_instance_name(full_name: &str, service_type: &str) -> String {
    let full = full_name.trim_end_matches('.');
    let service = service_type.trim_end_matches('.');

    if !service.is_empty() {
        let suffix_len = service.len() + 1;
        if full.len() > suffix_len && ends_with_ignore_case(full, service) {
            let cut = full.len() - suffix_len;
            if full.as_bytes()[cut] == b'.' {
                return full[..cut].to_string();
            }
        }
    }
    full.to_string()
}

pub(crate) fn short_hostname(hostname: &str) -> &str {
    let hostname = hostname.trim_end_matches('.');
    if ends_with_ignore_case(hostname, ".local") {
        &hostname[..hostname.len() - ".local".len()]
    } else {
        hostname
    }
}

pub(crate) fn dedup_key(
    hostname: &str,
    instance_name: &str,
    service_type: &str,
) -> (String, String) {
    let host = short_hostname(hostname);
    let base = if host.is_empty() { instance_name } else { host };
    (base.to_ascii_lowercase(), service_type.to_string())
}

pub(crate) fn first_non_empty<'a>(
    props: &'a HashMap<String, String>,
    candidates: &[&str],
) -> Option<&'a str> {
    candidates
        .iter()
        .filter_map(|k| props.get(*k))
        .map(|v| v.as_str())
        .find(|v| !v.is_empty())
}

pub(crate) fn build_device(
    instance_name: &str,
    hostname: &str,
    service_type: &str,
    port: Option<u16>,
    addresses: &[IpAddr],
    props: &HashMap<String, String>,
) -> DiscoveredDevice {
    let device_type = if let Some(class) = first_non_empty(props, &["DeviceClass", "deviceClass"]) {
        DeviceType::from_device_class(class)
    } else if let Some(model) = first_non_empty(props, &["ProductType", "model", "rpMd"]) {
        DeviceType::from_product_type(model)
    } else {
        DeviceType::Unknown
    };

    let product_type =
        first_non_empty(props, &["ProductType", "model", "rpMd"]).map(str::to_string);
    let os_version = first_non_empty(props, &["OSVersion", "osVersion"]).map(str::to_string);
    let udid = None;

    let name = {
        let from_host = short_hostname(hostname).replace('-', " ");
        if !from_host.is_empty() {
            from_host
        } else {
            first_non_empty(props, &["name", "Name"])
                .map(str::to_string)
                .unwrap_or_else(|| instance_name.to_string())
        }
    };

    DiscoveredDevice {
        name,
        hostname: short_hostname(hostname).to_string(),
        udid,
        ip_address: addresses
            .iter()
            .find(|address| address.is_ipv4())
            .or_else(|| addresses.first())
            .map(|address| address.to_string()),
        port,
        device_type,
        connection_type: ConnectionType::WiFi,
        is_paired: service_type.contains("mobdev2"),
        product_type,
        os_version,
        service_type: service_type.to_string(),
    }
}

pub(crate) fn is_metadata_service(service_type: &str) -> bool {
    METADATA_SERVICE_TYPES.contains(&service_type)
}

fn device_correlation_key(device: &DiscoveredDevice) -> String {
    if device.hostname.is_empty() {
        device.name.to_ascii_lowercase()
    } else {
        device.hostname.to_ascii_lowercase()
    }
}

pub(crate) fn enrich_and_filter(devices: Vec<DiscoveredDevice>) -> Vec<DiscoveredDevice> {
    let mut metadata: HashMap<String, DiscoveredDevice> = HashMap::new();
    for d in &devices {
        if !is_metadata_service(&d.service_type) {
            continue;
        }
        let key = device_correlation_key(d);
        let should_replace = match metadata.get(&key) {
            Some(existing) => existing.device_type == DeviceType::Unknown,
            None => true,
        };
        if should_replace {
            metadata.insert(key, d.clone());
        }
    }

    devices
        .into_iter()
        .filter(|d| !is_metadata_service(&d.service_type))
        .map(|mut d| {
            if let Some(meta) = metadata.get(&device_correlation_key(&d)) {
                let agrees = d.device_type == DeviceType::Unknown
                    || meta.device_type == DeviceType::Unknown
                    || d.device_type == meta.device_type;
                if agrees {
                    if d.device_type == DeviceType::Unknown {
                        d.device_type = meta.device_type.clone();
                    }
                    if d.product_type.is_none() {
                        d.product_type = meta.product_type.clone();
                    }
                    if d.os_version.is_none() {
                        d.os_version = meta.os_version.clone();
                    }
                }
            }
            d
        })
        .collect()
}

struct NetworkDeviceGroup {
    name: String,
    hostname: String,
    ip: Option<IpAddr>,
    pairing_port: Option<u16>,
    reconnect_port: Option<u16>,
}

pub fn group_network_devices(discovered: &[DiscoveredDevice], cache_dir: &Path) -> Vec<Device> {
    let mut groups: HashMap<String, NetworkDeviceGroup> = HashMap::new();

    for d in discovered {
        if d.device_type != DeviceType::AppleTV {
            continue;
        }
        let is_remote_pairing = d.service_type == REMOTEPAIRING_SERVICE
            || d.service_type == REMOTEPAIRING_MANUAL_PAIRING_SERVICE;
        let is_core_device = d.service_type == APPLE_MOBDEV2_SERVICE;
        if !is_remote_pairing && !is_core_device {
            continue;
        }
        if d.name.is_empty() {
            continue;
        }

        let key = if d.hostname.is_empty() {
            d.name.to_ascii_lowercase()
        } else {
            d.hostname.to_ascii_lowercase()
        };
        let entry = groups.entry(key).or_insert_with(|| NetworkDeviceGroup {
            name: d.name.clone(),
            hostname: d.hostname.clone(),
            ip: None,
            pairing_port: None,
            reconnect_port: None,
        });

        if entry.ip.is_none() {
            if let Some(ip_str) = &d.ip_address {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    entry.ip = Some(ip);
                }
            }
        }

        if d.service_type == REMOTEPAIRING_MANUAL_PAIRING_SERVICE {
            entry.pairing_port = d.port;
        } else if d.service_type == REMOTEPAIRING_SERVICE {
            entry.reconnect_port = d.port;
        }
    }

    let mut devices = Vec::with_capacity(groups.len());
    for group in groups.into_values() {
        let Some(ip) = group.ip else {
            continue;
        };
        let pairing_identity = if group.hostname.is_empty() {
            group.name.replace(' ', "-")
        } else {
            group.hostname
        };
        let id = synthetic_device_id(&pairing_identity);

        let mut device = Device::new_tvos(
            group.name,
            pairing_identity,
            ip,
            group.pairing_port,
            group.reconnect_port,
            cache_dir.to_path_buf(),
        );
        device.device_id = id;

        devices.push(device);
    }

    devices
}

pub fn disconnected_after_missed_scans(
    present_ids: &mut HashSet<u32>,
    current_ids: &HashSet<u32>,
    miss_counts: &mut HashMap<u32, u32>,
    required_misses: u32,
) -> Vec<u32> {
    for id in current_ids {
        miss_counts.remove(id);
    }

    let missing = present_ids
        .iter()
        .copied()
        .filter(|id| !current_ids.contains(id))
        .collect::<Vec<_>>();
    let threshold = required_misses.max(1);
    let mut disconnected = Vec::new();

    for id in missing {
        let misses = miss_counts.entry(id).or_insert(0);
        *misses += 1;
        if *misses >= threshold {
            present_ids.remove(&id);
            miss_counts.remove(&id);
            disconnected.push(id);
        }
    }

    disconnected
}

#[allow(async_fn_in_trait)]
pub trait DeviceDiscovery {
    async fn discover(&self, timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformDiscovery;

impl PlatformDiscovery {
    pub fn new() -> Self {
        Self
    }
}

impl DeviceDiscovery for PlatformDiscovery {
    async fn discover(&self, timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>> {
        mdns::MdnsDiscovery::new().discover(timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn instance_name_strips_service_suffix() {
        assert_eq!(
            parse_instance_name(
                "Living Room._remotepairing-manual-pairing._tcp.local",
                REMOTEPAIRING_MANUAL_PAIRING_SERVICE
            ),
            "Living Room"
        );
    }

    #[test]
    fn instance_name_handles_trailing_dot_on_both_sides() {
        assert_eq!(
            parse_instance_name("Apple TV._remotepairing._tcp.local.", REMOTEPAIRING_SERVICE),
            "Apple TV"
        );
        assert_eq!(
            parse_instance_name(
                "Apple TV._remotepairing._tcp.local",
                "_remotepairing._tcp.local"
            ),
            "Apple TV"
        );
    }

    #[test]
    fn instance_name_keeps_literal_non_ascii() {
        let full = "Frankie\u{2019}s MacBook Pro._companion-link._tcp.local";
        assert_eq!(
            parse_instance_name(full, "_companion-link._tcp.local."),
            "Frankie\u{2019}s MacBook Pro"
        );
    }

    #[test]
    fn instance_name_left_alone_when_suffix_absent() {
        assert_eq!(
            parse_instance_name("Living Room._other._tcp.local", REMOTEPAIRING_SERVICE),
            "Living Room._other._tcp.local"
        );
    }

    #[test]
    fn instance_name_does_not_split_a_multibyte_character() {
        let name = "\u{2019}".to_string() + &"X".repeat(24);
        assert_eq!(parse_instance_name(&name, REMOTEPAIRING_SERVICE), name);

        for pad in 0..8 {
            let name = "A".repeat(pad) + "\u{2019}\u{2019}\u{2019}";
            assert_eq!(parse_instance_name(&name, "_x._tcp.local"), name);
        }
    }

    #[test]
    fn suffix_match_is_case_insensitive() {
        assert!(ends_with_ignore_case(
            "Living Room._TCP.LOCAL",
            "_tcp.local"
        ));
        assert!(ends_with_ignore_case("abc", "ABC"));
        assert!(!ends_with_ignore_case("abc", "abd"));
        assert!(!ends_with_ignore_case("ab", "abc"));
        assert_eq!(
            parse_instance_name(
                "Living Room._RemotePairing._TCP.local",
                REMOTEPAIRING_SERVICE
            ),
            "Living Room"
        );
    }

    #[test]
    fn short_hostname_strips_local_suffix_without_case_sensitivity() {
        assert_eq!(short_hostname("Apple-TV.LOCAL."), "Apple-TV");
        assert_eq!(short_hostname("Apple-TV.example"), "Apple-TV.example");
    }

    #[test]
    fn first_non_empty_skips_present_but_empty_values() {
        let p = props(&[("ProductType", ""), ("model", "AppleTV14,1")]);
        assert_eq!(
            first_non_empty(&p, &["ProductType", "model"]),
            Some("AppleTV14,1")
        );
        assert_eq!(first_non_empty(&p, &["ProductType"]), None);
        assert_eq!(first_non_empty(&p, &["absent"]), None);
    }

    #[test]
    fn real_apple_tv_txt_maps_to_apple_tv() {
        let manual = props(&[("model", "AppleTV14,1")]);
        let d = build_device(
            "Living Room",
            "Living-Room.local.",
            REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
            Some(49153),
            &[],
            &manual,
        );
        assert_eq!(d.device_type, DeviceType::AppleTV);
        assert_eq!(d.product_type.as_deref(), Some("AppleTV14,1"));

        let companion = props(&[("rpMd", "AppleTV14,1"), ("udid", "deadbeef")]);
        let d = build_device(
            "Living Room",
            "Living-Room.local.",
            REMOTEPAIRING_SERVICE,
            Some(49152),
            &[],
            &companion,
        );
        assert_eq!(d.device_type, DeviceType::AppleTV);
        assert_eq!(d.product_type.as_deref(), Some("AppleTV14,1"));
        assert_eq!(d.udid, None);
    }

    #[test]
    fn mapping_prefers_device_class() {
        let p = props(&[
            ("DeviceClass", "AppleTV"),
            ("ProductType", "AppleTV11,1"),
            ("UniqueDeviceID", "abc123"),
            ("OSVersion", "17.4"),
            ("name", "Ignored"),
        ]);
        let d = build_device(
            "Living Room",
            "Living-Room.local.",
            REMOTEPAIRING_SERVICE,
            Some(49152),
            &["10.0.0.5".parse::<IpAddr>().unwrap()],
            &p,
        );
        assert_eq!(d.device_type, DeviceType::AppleTV);
        assert_eq!(d.product_type.as_deref(), Some("AppleTV11,1"));
        assert_eq!(d.os_version.as_deref(), Some("17.4"));
        assert_eq!(d.udid, None);
        assert_eq!(d.ip_address.as_deref(), Some("10.0.0.5"));
        assert_eq!(d.port, Some(49152));
        assert_eq!(d.connection_type, ConnectionType::WiFi);
        assert!(!d.is_paired);
        assert_eq!(d.service_type, REMOTEPAIRING_SERVICE);
    }

    #[test]
    fn mapping_prefers_ipv4_over_unscoped_link_local_ipv6() {
        let d = build_device(
            "TV",
            "TV.local.",
            REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
            Some(63295),
            &[
                "fe80::1020:429f:1e8:d85d".parse::<IpAddr>().unwrap(),
                "192.168.2.150".parse::<IpAddr>().unwrap(),
            ],
            &props(&[("model", "AppleTV14,1")]),
        );

        assert_eq!(d.ip_address.as_deref(), Some("192.168.2.150"));
    }

    #[test]
    fn mapping_name_prefers_hostname_over_txt_and_instance() {
        let d = build_device(
            "A827F07B-2D1D-4D09-8E1E-5E37EE47A96C",
            "Living-Room.local.",
            REMOTEPAIRING_SERVICE,
            Some(1),
            &[],
            &props(&[("name", "Some Other Name")]),
        );
        assert_eq!(d.name, "Living Room");
    }

    #[test]
    fn mapping_name_falls_back_when_hostname_missing() {
        let d = build_device(
            "instance-label",
            "",
            REMOTEPAIRING_SERVICE,
            Some(1),
            &[],
            &props(&[("name", "Txt Name")]),
        );
        assert_eq!(d.name, "Txt Name");

        let d = build_device(
            "instance-label",
            "",
            REMOTEPAIRING_SERVICE,
            Some(1),
            &[],
            &props(&[]),
        );
        assert_eq!(d.name, "instance-label");
    }

    #[test]
    fn same_device_yields_identical_name_across_service_types() {
        let manual = build_device(
            "Living Room",
            "Living-Room.local.",
            REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
            Some(62782),
            &[],
            &props(&[("name", "Living Room"), ("model", "AppleTV14,1")]),
        );
        let reconnect = build_device(
            "A827F07B-2D1D-4D09-8E1E-5E37EE47A96C",
            "Living-Room.local.",
            REMOTEPAIRING_SERVICE,
            Some(49152),
            &[],
            &props(&[("identifier", "73B8BE56-3881-4145-BF61-EFB7BBAEC98F")]),
        );

        assert_eq!(manual.name, "Living Room");
        assert_eq!(manual.name, reconnect.name);
        assert_ne!(manual.service_type, reconnect.service_type);
        assert_eq!(manual.port, Some(62782));
        assert_eq!(reconnect.port, Some(49152));
    }

    #[test]
    fn mapping_marks_mobdev2_as_paired() {
        let d = build_device(
            "x",
            "",
            APPLE_MOBDEV2_SERVICE,
            Some(62078),
            &[],
            &props(&[]),
        );
        assert!(d.is_paired);
        assert_eq!(d.device_type, DeviceType::Unknown);
        assert_eq!(d.product_type, None);
    }

    #[test]
    fn mapping_does_not_trust_advertised_udid() {
        let p = props(&[("udid", "second"), ("identifier", "third")]);
        assert_eq!(
            build_device("x", "", REMOTEPAIRING_SERVICE, Some(1), &[], &p).udid,
            None
        );
        let p = props(&[("identifier", "third")]);
        assert_eq!(
            build_device("x", "", REMOTEPAIRING_SERVICE, Some(1), &[], &p).udid,
            None
        );
    }

    #[test]
    fn dedup_key_normalizes_case_and_falls_back_to_instance() {
        assert_eq!(
            dedup_key("Living-Room.local.", "Living Room", REMOTEPAIRING_SERVICE),
            dedup_key("living-room.local", "Living Room", REMOTEPAIRING_SERVICE)
        );
        assert_eq!(
            dedup_key("", "Living Room", REMOTEPAIRING_SERVICE),
            ("living room".to_string(), REMOTEPAIRING_SERVICE.to_string())
        );
    }

    #[test]
    fn same_device_under_two_service_types_is_not_collapsed() {
        let p = props(&[("model", "AppleTV14,1")]);
        let mut devices: HashMap<(String, String), DiscoveredDevice> = HashMap::new();

        for (service, port) in [
            (REMOTEPAIRING_SERVICE, 49152u16),
            (REMOTEPAIRING_MANUAL_PAIRING_SERVICE, 49153u16),
        ] {
            let device = build_device(
                "Living Room",
                "Living-Room.local.",
                service,
                Some(port),
                &[],
                &p,
            );
            devices.insert(
                dedup_key("Living-Room.local.", "Living Room", service),
                device,
            );
        }

        assert_eq!(devices.len(), 2);
        let mut ports: Vec<u16> = devices.values().filter_map(|d| d.port).collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![49152, 49153]);
        assert!(devices.values().all(|d| d.name == "Living Room"));
    }

    fn unknown_device(name: &str, service_type: &str, port: u16) -> DiscoveredDevice {
        DiscoveredDevice {
            name: name.to_string(),
            hostname: String::new(),
            udid: None,
            ip_address: None,
            port: Some(port),
            device_type: DeviceType::Unknown,
            connection_type: ConnectionType::WiFi,
            is_paired: false,
            product_type: None,
            os_version: None,
            service_type: service_type.to_string(),
        }
    }

    fn companion_link_device(name: &str, product_type: &str) -> DiscoveredDevice {
        DiscoveredDevice {
            name: name.to_string(),
            hostname: String::new(),
            udid: None,
            ip_address: None,
            port: Some(49155),
            device_type: DeviceType::from_product_type(product_type),
            connection_type: ConnectionType::WiFi,
            is_paired: false,
            product_type: Some(product_type.to_string()),
            os_version: None,
            service_type: COMPANION_LINK_SERVICE.to_string(),
        }
    }

    #[test]
    fn enrich_and_filter_fills_model_from_companion_link() {
        let remotepairing = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 49152);
        let companion = companion_link_device("Living Room", "AppleTV14,1");

        let result = enrich_and_filter(vec![remotepairing, companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].service_type, REMOTEPAIRING_SERVICE);
        assert_eq!(result[0].port, Some(49152));
        assert_eq!(result[0].device_type, DeviceType::AppleTV);
        assert_eq!(result[0].product_type.as_deref(), Some("AppleTV14,1"));
    }

    #[test]
    fn enrich_and_filter_name_correlation_is_case_insensitive() {
        let remotepairing = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 49152);
        let companion = companion_link_device("living room", "AppleTV14,1");

        let result = enrich_and_filter(vec![remotepairing, companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].device_type, DeviceType::AppleTV);
        assert_eq!(result[0].product_type.as_deref(), Some("AppleTV14,1"));
    }

    #[test]
    fn enrich_and_filter_does_not_overwrite_known_device_type() {
        let mut manual = unknown_device("Living Room", REMOTEPAIRING_MANUAL_PAIRING_SERVICE, 49153);
        manual.device_type = DeviceType::AppleTV;
        let mut companion = companion_link_device("Living Room", "iPhone15,2");
        companion.device_type = DeviceType::IPhone;

        let result = enrich_and_filter(vec![manual, companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].device_type, DeviceType::AppleTV);
        assert_eq!(result[0].product_type, None);
    }

    #[test]
    fn enrich_and_filter_prefers_a_typed_metadata_entry_regardless_of_order() {
        for reversed in [false, true] {
            let target = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 49152);
            let untyped = companion_link_device("Living Room", "");
            let mut untyped = untyped;
            untyped.device_type = DeviceType::Unknown;
            untyped.product_type = None;
            let typed = companion_link_device("Living Room", "AppleTV14,1");

            let input = if reversed {
                vec![target, typed, untyped]
            } else {
                vec![target, untyped, typed]
            };
            let result = enrich_and_filter(input);

            assert_eq!(result.len(), 1);
            assert_eq!(
                result[0].device_type,
                DeviceType::AppleTV,
                "reversed={reversed}"
            );
            assert_eq!(
                result[0].product_type.as_deref(),
                Some("AppleTV14,1"),
                "reversed={reversed}"
            );
        }
    }

    #[test]
    fn enrich_and_filter_does_not_overwrite_known_product_type() {
        let mut remotepairing = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 49152);
        remotepairing.product_type = Some("x".to_string());
        let companion = companion_link_device("Living Room", "AppleTV14,1");

        let result = enrich_and_filter(vec![remotepairing, companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].product_type.as_deref(), Some("x"));
    }

    #[test]
    fn enrich_and_filter_drops_unmatched_metadata_entries() {
        let companion = companion_link_device("Living Room", "AppleTV14,1");

        let result = enrich_and_filter(vec![companion]);

        assert!(result.is_empty());
    }

    #[test]
    fn enrich_and_filter_does_not_cross_contaminate_hosts() {
        let bedroom = unknown_device("Bedroom", REMOTEPAIRING_SERVICE, 49152);
        let living_room_companion = companion_link_device("Living Room", "AppleTV14,1");

        let result = enrich_and_filter(vec![bedroom, living_room_companion]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "Bedroom");
        assert_eq!(result[0].device_type, DeviceType::Unknown);
        assert_eq!(result[0].product_type, None);
    }

    #[test]
    fn enrich_and_filter_preserves_order_of_non_metadata_entries() {
        let bedroom = unknown_device("Bedroom", REMOTEPAIRING_SERVICE, 1);
        let companion = companion_link_device("Living Room", "AppleTV14,1");
        let living_room = unknown_device("Living Room", REMOTEPAIRING_SERVICE, 2);
        let kitchen = unknown_device("Kitchen", REMOTEPAIRING_SERVICE, 3);

        let result = enrich_and_filter(vec![bedroom, companion, living_room, kitchen]);

        assert_eq!(
            result.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["Bedroom", "Living Room", "Kitchen"]
        );
    }

    fn network_apple_tv(name: &str, service_type: &str, port: u16, ip: &str) -> DiscoveredDevice {
        DiscoveredDevice {
            name: name.to_string(),
            hostname: name.replace(' ', "-").to_ascii_lowercase(),
            udid: None,
            ip_address: Some(ip.to_string()),
            port: Some(port),
            device_type: DeviceType::AppleTV,
            connection_type: ConnectionType::WiFi,
            is_paired: false,
            product_type: Some("AppleTV14,1".to_string()),
            os_version: None,
            service_type: service_type.to_string(),
        }
    }

    #[test]
    fn group_network_devices_only_manual_sets_pairing_port_only() {
        let discovered = [network_apple_tv(
            "Living Room",
            REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
            49153,
            "10.0.0.5",
        )];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].pairing_address,
            Some(("10.0.0.5".parse().unwrap(), 49153))
        );
        assert_eq!(devices[0].reconnect_address, None);
    }

    #[test]
    fn group_network_devices_only_reconnect_sets_reconnect_port_only() {
        let discovered = [network_apple_tv(
            "Living Room",
            REMOTEPAIRING_SERVICE,
            49152,
            "10.0.0.5",
        )];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].reconnect_address,
            Some(("10.0.0.5".parse().unwrap(), 49152))
        );
        assert_eq!(devices[0].pairing_address, None);
    }

    #[test]
    fn group_network_devices_merges_both_service_types_into_one_device() {
        let discovered = [
            network_apple_tv(
                "Living Room",
                REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
                49153,
                "10.0.0.5",
            ),
            network_apple_tv("living room", REMOTEPAIRING_SERVICE, 49152, "10.0.0.5"),
        ];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pairing_address.map(|(_, p)| p), Some(49153));
        assert_eq!(devices[0].reconnect_address.map(|(_, p)| p), Some(49152));
    }

    #[test]
    fn group_network_devices_deduplicates_legacy_core_device_with_remote_pairing() {
        let discovered = [
            network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 49152, "10.0.0.5"),
            network_apple_tv("Living Room", APPLE_MOBDEV2_SERVICE, 62078, "10.0.0.5"),
        ];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].reconnect_address.unwrap().1, 49152);
        assert_eq!(devices[0].pairing_identity.as_deref(), Some("living-room"));
    }

    #[test]
    fn group_network_devices_retains_legacy_core_device_until_authenticated_data_arrives() {
        let discovered = [network_apple_tv(
            "Living Room",
            APPLE_MOBDEV2_SERVICE,
            62078,
            "10.0.0.5",
        )];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert!(devices[0].pairing_address.is_none());
        assert!(devices[0].reconnect_address.is_none());
        assert!(devices[0].udid.is_empty());
    }

    #[test]
    fn group_network_devices_keeps_same_named_hosts_separate() {
        let mut first = network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 49152, "10.0.0.5");
        let mut second = network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 49152, "10.0.0.6");
        first.hostname = "living-room-a".to_string();
        second.hostname = "living-room-b".to_string();

        let devices = group_network_devices(&[first, second], Path::new("/cache"));

        assert_eq!(devices.len(), 2);
        assert_ne!(devices[0].pairing_identity, devices[1].pairing_identity);
    }

    #[test]
    fn disappearing_mdns_service_requires_two_missed_scans() {
        let mut present = [7u32].into_iter().collect::<HashSet<_>>();
        let empty = HashSet::new();
        let mut misses = HashMap::new();

        assert!(disconnected_after_missed_scans(&mut present, &empty, &mut misses, 2).is_empty());
        assert_eq!(disconnected_after_missed_scans(&mut present, &empty, &mut misses, 2), vec![7]);
        assert!(present.is_empty());
        assert!(misses.is_empty());
    }

    #[test]
    fn rediscovered_mdns_service_clears_missed_scan_count() {
        let mut present = [7u32].into_iter().collect::<HashSet<_>>();
        let empty = HashSet::new();
        let current = [7u32].into_iter().collect::<HashSet<_>>();
        let mut misses = HashMap::new();

        assert!(disconnected_after_missed_scans(&mut present, &empty, &mut misses, 2).is_empty());
        assert!(disconnected_after_missed_scans(&mut present, &current, &mut misses, 2).is_empty());
        assert!(present.contains(&7));
    }

    #[test]
    fn group_network_devices_excludes_non_appletv() {
        let mut d = network_apple_tv("Some iPhone", REMOTEPAIRING_SERVICE, 1, "10.0.0.5");
        d.device_type = DeviceType::IPhone;

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert!(devices.is_empty());
    }

    #[test]
    fn group_network_devices_excludes_unsupported_service() {
        let d = network_apple_tv("Living Room", APPLE_PAIRABLE_SERVICE, 62078, "10.0.0.5");

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert!(devices.is_empty());
    }

    #[test]
    fn group_network_devices_keeps_two_different_apple_tvs_separate() {
        let discovered = [
            network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 1, "10.0.0.5"),
            network_apple_tv("Bedroom", REMOTEPAIRING_SERVICE, 2, "10.0.0.6"),
        ];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 2);
        let mut names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["Bedroom", "Living Room"]);
    }

    #[test]
    fn group_network_devices_skips_empty_name() {
        let d = network_apple_tv("", REMOTEPAIRING_SERVICE, 1, "10.0.0.5");

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert!(devices.is_empty());
    }

    #[test]
    fn group_network_devices_skips_unresolved_ip() {
        let mut d = network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 1, "10.0.0.5");
        d.ip_address = None;

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert!(devices.is_empty());
    }

    #[test]
    fn group_network_devices_sets_synthetic_device_id_and_pairing_identity() {
        let d = network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 1, "10.0.0.5");

        let devices = group_network_devices(&[d], Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pairing_identity.as_deref(), Some("living-room"));
        assert_eq!(devices[0].device_id, synthetic_device_id("living-room"));
        assert_ne!(devices[0].device_id, 0);
    }

    #[test]
    fn group_network_devices_keeps_first_resolved_address_when_entries_share_a_name() {
        let discovered = [
            network_apple_tv(
                "Living Room",
                REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
                49153,
                "10.0.0.5",
            ),
            network_apple_tv("Living Room", REMOTEPAIRING_SERVICE, 49152, "10.0.0.9"),
        ];

        let devices = group_network_devices(&discovered, Path::new("/cache"));

        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].pairing_address.unwrap().0.to_string(),
            "10.0.0.5"
        );
        assert_eq!(
            devices[0].reconnect_address.unwrap().0.to_string(),
            "10.0.0.5"
        );
    }
}
