#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingFailure {
    Cancelled,
    InvalidPin,
    WrongPin,
    StaleRecord,
    ServiceDisappeared,
    Protocol(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingStage {
    Reconnected,
    Paired,
}

#[allow(async_fn_in_trait)]
pub trait PairingBackend {
    async fn verify(&mut self) -> Result<(), PairingFailure>;
    async fn pair(&mut self, pin: &str) -> Result<(), PairingFailure>;
}

pub async fn ensure_pairing<B, F, Fut>(
    backend: &mut B,
    has_cached_record: bool,
    has_pairing_service: bool,
    has_reconnect_service: bool,
    pin_provider: F,
) -> Result<PairingStage, PairingFailure>
where
    B: PairingBackend,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = String>,
{
    if has_cached_record && (has_reconnect_service || has_pairing_service) {
        if backend.verify().await.is_ok() {
            return Ok(PairingStage::Reconnected);
        }
        if !has_pairing_service {
            return Err(PairingFailure::StaleRecord);
        }
    }

    if !has_pairing_service {
        return Err(PairingFailure::ServiceDisappeared);
    }

    let pin = pin_provider().await;
    if pin.is_empty() {
        return Err(PairingFailure::Cancelled);
    }
    if pin.len() != 6 || !pin.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PairingFailure::InvalidPin);
    }

    backend.pair(&pin).await?;
    Ok(PairingStage::Paired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct MockPairingBackend {
        verify_results: VecDeque<Result<(), PairingFailure>>,
        pair_results: VecDeque<Result<(), PairingFailure>>,
        verify_calls: usize,
        pair_calls: Vec<String>,
    }

    impl MockPairingBackend {
        fn new(
            verify_results: impl IntoIterator<Item = Result<(), PairingFailure>>,
            pair_results: impl IntoIterator<Item = Result<(), PairingFailure>>,
        ) -> Self {
            Self {
                verify_results: verify_results.into_iter().collect(),
                pair_results: pair_results.into_iter().collect(),
                verify_calls: 0,
                pair_calls: Vec::new(),
            }
        }
    }

    impl PairingBackend for MockPairingBackend {
        async fn verify(&mut self) -> Result<(), PairingFailure> {
            self.verify_calls += 1;
            self.verify_results.pop_front().unwrap_or(Ok(()))
        }

        async fn pair(&mut self, pin: &str) -> Result<(), PairingFailure> {
            self.pair_calls.push(pin.to_string());
            self.pair_results.pop_front().unwrap_or(Ok(()))
        }
    }

    #[tokio::test]
    async fn first_pairing_uses_manual_service_and_pin_once() {
        let mut backend = MockPairingBackend::new([], [Ok(())]);

        let stage = ensure_pairing(&mut backend, false, true, false, || async {
            "123456".to_string()
        })
        .await
        .unwrap();

        assert_eq!(stage, PairingStage::Paired);
        assert_eq!(backend.verify_calls, 0);
        assert_eq!(backend.pair_calls, vec!["123456"]);
    }

    #[tokio::test]
    async fn saved_record_reconnects_without_requesting_pin() {
        let mut backend = MockPairingBackend::new([Ok(())], []);
        let mut requested_pin = false;

        let stage = ensure_pairing(&mut backend, true, false, true, || async {
            requested_pin = true;
            "123456".to_string()
        })
        .await
        .unwrap();

        assert_eq!(stage, PairingStage::Reconnected);
        assert_eq!(backend.verify_calls, 1);
        assert!(backend.pair_calls.is_empty());
        assert!(!requested_pin);
    }

    #[tokio::test]
    async fn wrong_pin_is_returned_before_any_installation_step() {
        let mut backend = MockPairingBackend::new([], [Err(PairingFailure::WrongPin)]);

        let error = ensure_pairing(&mut backend, false, true, false, || async {
            "654321".to_string()
        })
        .await
        .unwrap_err();

        assert_eq!(error, PairingFailure::WrongPin);
        assert_eq!(backend.pair_calls, vec!["654321"]);
    }

    #[tokio::test]
    async fn cancelled_pin_does_not_call_pairing_backend() {
        let mut backend = MockPairingBackend::new([], []);

        let error = ensure_pairing(&mut backend, false, true, false, || async {
            String::new()
        })
        .await
        .unwrap_err();

        assert_eq!(error, PairingFailure::Cancelled);
        assert!(backend.pair_calls.is_empty());
    }

    #[tokio::test]
    async fn stale_record_needs_manual_service_before_retrying_pairing() {
        let mut backend = MockPairingBackend::new([Err(PairingFailure::Protocol("stale".into()))], []);

        let error = ensure_pairing(&mut backend, true, false, true, || async {
            "123456".to_string()
        })
        .await
        .unwrap_err();

        assert_eq!(error, PairingFailure::StaleRecord);
        assert!(backend.pair_calls.is_empty());
    }

    #[tokio::test]
    async fn disappearing_service_is_not_treated_as_a_pairing_failure() {
        let mut backend = MockPairingBackend::new([], []);

        let error = ensure_pairing(&mut backend, false, false, true, || async {
            "123456".to_string()
        })
        .await
        .unwrap_err();

        assert_eq!(error, PairingFailure::ServiceDisappeared);
        assert!(backend.pair_calls.is_empty());
    }
}
