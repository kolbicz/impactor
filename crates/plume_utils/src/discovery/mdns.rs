use super::{
    ALL_SCANNED_SERVICE_TYPES, DeviceDiscovery, DiscoveredDevice, build_device, enrich_and_filter,
    dedup_key, parse_instance_name,
};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::time::Duration;

pub use super::{
    APPLE_MOBDEV2_SERVICE, APPLE_PAIRABLE_SERVICE, REMOTEPAIRING_MANUAL_PAIRING_SERVICE,
    REMOTEPAIRING_SERVICE,
};

pub struct MdnsDiscovery {
    service_types: Vec<String>,
}

impl MdnsDiscovery {
    pub fn new() -> Self {
        Self {
            service_types: ALL_SCANNED_SERVICE_TYPES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl Default for MdnsDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceDiscovery for MdnsDiscovery {
    async fn discover(&self, timeout: Duration) -> crate::Result<Vec<DiscoveredDevice>> {
        let mdns = ServiceDaemon::new()
            .map_err(|e| crate::Error::Other(format!("Failed to create mDNS daemon: {e}")))?;

        let mut receivers = Vec::new();
        for service_type in &self.service_types {
            match mdns.browse(service_type) {
                Ok(receiver) => receivers.push((service_type.clone(), receiver)),
                Err(e) => {
                    log::warn!("Failed to browse {service_type}: {e}");
                }
            }
        }

        let service_types = self.service_types.clone();
        let discovered = tokio::task::spawn_blocking(move || {
            let mut discovered_devices: HashMap<(String, String), DiscoveredDevice> =
                HashMap::new();
            let deadline = std::time::Instant::now() + timeout;

            while std::time::Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let poll_time = remaining.min(Duration::from_millis(200));
                let mut got_event = false;

                for (service_type, receiver) in &receivers {
                    match receiver.recv_timeout(poll_time) {
                        Ok(ServiceEvent::ServiceResolved(info)) => {
                            got_event = true;
                            let properties: HashMap<String, String> = info
                                .get_properties()
                                .iter()
                                .map(|p| (p.key().to_string(), p.val_str().to_string()))
                                .collect();

                            let hostname = info.get_hostname();
                            let instance_name =
                                parse_instance_name(info.get_fullname(), service_type);
                            let addresses: Vec<std::net::IpAddr> =
                                info.get_addresses().iter().copied().collect();
                            let port = Some(info.get_port());

                            let device = build_device(
                                &instance_name,
                                hostname,
                                service_type,
                                port,
                                &addresses,
                                &properties,
                            );

                            log::debug!(
                                "mDNS resolved: hostname={} service={} ip={:?} port={:?}",
                                hostname,
                                service_type,
                                device.ip_address,
                                port
                            );

                            let key = dedup_key(hostname, &instance_name, service_type);

                            discovered_devices.insert(key, device);
                        }
                        Ok(_) => {
                            got_event = true;
                        }
                        Err(_) => {}
                    }
                }

                if !got_event && poll_time == remaining {
                    break;
                }
            }

            for stype in &service_types {
                let _ = mdns.stop_browse(stype);
            }
            let _ = mdns.shutdown();

            discovered_devices
        })
        .await
        .map_err(|e| crate::Error::Other(format!("mDNS scan task failed: {e}")))?;

        Ok(enrich_and_filter(discovered.into_values().collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DeviceType;

    #[test]
    fn test_device_type_from_class() {
        assert_eq!(
            DeviceType::from_device_class("AppleTV"),
            DeviceType::AppleTV
        );
        assert_eq!(DeviceType::from_device_class("iPhone"), DeviceType::IPhone);
    }

    #[test]
    fn test_device_type_from_product() {
        assert_eq!(
            DeviceType::from_product_type("AppleTV11,1"),
            DeviceType::AppleTV
        );
        assert_eq!(
            DeviceType::from_product_type("iPhone15,2"),
            DeviceType::IPhone
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_mdns_discovery() {
        let discovery = MdnsDiscovery::new();
        let devices = discovery.discover(Duration::from_secs(5)).await.unwrap();
        println!("Discovered {} devices:", devices.len());
        for device in &devices {
            println!("  - {} ({:?})", device.name, device.device_type);
        }
    }
}
