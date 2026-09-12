use plist::{Dictionary, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeveloperPlatform {
    #[default]
    Ios,
    Tvos,
}

impl DeveloperPlatform {
    pub fn from_device_metadata(
        product_type: Option<&str>,
        device_class: Option<&str>,
        network_transport: bool,
    ) -> Self {
        if network_transport
            || product_type.is_some_and(|value| value.starts_with("AppleTV"))
            || device_class.is_some_and(|value| value.eq_ignore_ascii_case("AppleTV"))
        {
            Self::Tvos
        } else {
            Self::Ios
        }
    }

    pub fn request_fields(self) -> &'static [(&'static str, &'static str)] {
        match self {
            DeveloperPlatform::Ios => &[],
            DeveloperPlatform::Tvos => &[("DTDK_Platform", "tvos"), ("subPlatform", "tvOS")],
        }
    }

    pub fn apply_to(self, body: &mut Dictionary) {
        let fields = self.request_fields();
        if fields.is_empty() {
            return;
        }
        for (key, value) in fields {
            body.insert((*key).to_string(), Value::String((*value).to_string()));
        }
    }

    pub fn profile_platforms(self) -> &'static [&'static str] {
        match self {
            Self::Ios => &["ios", "iphoneos"],
            Self::Tvos => &["tvos"],
        }
    }

    pub fn matches_profile_platform(self, value: &str) -> bool {
        self.profile_platforms()
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(value))
    }
}

impl std::fmt::Display for DeveloperPlatform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeveloperPlatform::Ios => formatter.write_str("iOS"),
            DeveloperPlatform::Tvos => formatter.write_str("tvOS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ios() {
        assert_eq!(DeveloperPlatform::default(), DeveloperPlatform::Ios);
    }

    #[test]
    fn ios_request_fields_are_empty() {
        assert!(DeveloperPlatform::Ios.request_fields().is_empty());
    }

    #[test]
    fn tvos_request_fields_are_exact() {
        assert_eq!(
            DeveloperPlatform::Tvos.request_fields(),
            &[("DTDK_Platform", "tvos"), ("subPlatform", "tvOS")]
        );
    }

    #[test]
    fn ios_apply_to_leaves_dictionary_unchanged() {
        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String("T123".to_string()));
        body.insert("appIdId".to_string(), Value::String("A456".to_string()));
        let original = body.clone();

        DeveloperPlatform::Ios.apply_to(&mut body);

        assert_eq!(body, original);
        assert_eq!(body.keys().count(), 2);
    }

    #[test]
    fn tvos_apply_to_adds_exactly_the_two_platform_fields() {
        let mut body = Dictionary::new();
        body.insert("teamId".to_string(), Value::String("T123".to_string()));
        body.insert("appIdId".to_string(), Value::String("A456".to_string()));

        DeveloperPlatform::Tvos.apply_to(&mut body);

        assert_eq!(body.keys().count(), 4);
        assert_eq!(body.get("teamId").and_then(Value::as_string), Some("T123"));
        assert_eq!(body.get("appIdId").and_then(Value::as_string), Some("A456"));
        assert_eq!(
            body.get("DTDK_Platform").and_then(Value::as_string),
            Some("tvos")
        );
        assert_eq!(
            body.get("subPlatform").and_then(Value::as_string),
            Some("tvOS")
        );
    }

    #[test]
    fn metadata_classifies_tvos_without_trusting_network_identifiers() {
        assert_eq!(
            DeveloperPlatform::from_device_metadata(
                Some("AppleTV14,1"),
                Some("AppleTV"),
                false
            ),
            DeveloperPlatform::Tvos
        );
        assert_eq!(
            DeveloperPlatform::from_device_metadata(None, None, true),
            DeveloperPlatform::Tvos
        );
        assert_eq!(
            DeveloperPlatform::from_device_metadata(Some("iPhone15,2"), Some("iPhone"), false),
            DeveloperPlatform::Ios
        );
    }

    #[test]
    fn profile_platform_matching_is_case_insensitive() {
        assert!(DeveloperPlatform::Tvos.matches_profile_platform("tvOS"));
        assert!(!DeveloperPlatform::Tvos.matches_profile_platform("iOS"));
        assert!(DeveloperPlatform::Ios.matches_profile_platform("iPhoneOS"));
    }
}
