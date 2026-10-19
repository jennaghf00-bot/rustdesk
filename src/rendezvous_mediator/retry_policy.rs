use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct UdpProbe {
    last_accepted: Instant,
    registered: bool,
}

impl UdpProbe {
    pub(crate) fn new(started: Instant) -> Self {
        Self {
            last_accepted: started,
            registered: false,
        }
    }
    pub(crate) fn accepted(&mut self, now: Instant) {
        self.last_accepted = now;
        self.registered = true;
    }
    pub(crate) fn heartbeat(&mut self, now: Instant) {
        if self.registered {
            self.last_accepted = now;
        }
    }
    pub(crate) fn require_registration(&mut self, now: Instant) {
        if self.registered {
            self.last_accepted = now;
        }
        self.registered = false;
    }
    pub(crate) fn expired(&self, now: Instant) -> bool {
        acknowledgement_expired(self.last_accepted, now, Duration::from_secs(12))
    }
}

pub(crate) fn acknowledgement_expired(last: Instant, now: Instant, limit: Duration) -> bool {
    now.checked_duration_since(last)
        .map(|age| age >= limit)
        .unwrap_or(true)
}

#[derive(Default)]
pub(crate) struct RetryPolicy {
    failures: u8,
    tcp_only: bool,
}

impl RetryPolicy {
    pub(crate) fn prefer_tcp(&mut self) {
        self.tcp_only = true;
    }
    pub(crate) fn should_probe_udp(&self) -> bool {
        !self.tcp_only
    }
    pub(crate) fn reset_backoff(&mut self) {
        self.failures = 0;
    }
    pub(crate) fn record_tcp_error(&mut self, code: &str) {
        self.record_error(code);
        if matches!(code, "identity_mismatch" | "private_tcp_invalid_identity") {
            self.prefer_tcp();
        }
    }
    pub(crate) fn record_error(&mut self, code: &str) {
        if matches!(
            code,
            "private_tcp_server_identity_mismatch"
                | "private_tcp_invalid_frame"
                | "private_tcp_unencrypted_message"
                | "private_tcp_device_proof_invalid"
                | "private_tcp_registration_failed"
                | "private_tcp_invalid_challenge"
                | "private_tcp_unexpected_registration"
                | "private_tcp_key_exchange_failed"
                | "private_tcp_unsupported_version"
                | "private_tcp_transport_mismatch"
        ) {
            self.prefer_tcp();
        }
    }
    pub(crate) fn delay(&mut self, jitter: u32) -> Duration {
        let base = (2u64 << self.failures.min(8)).min(300);
        self.failures = self.failures.saturating_add(1);
        Duration::from_secs((base + u64::from(jitter) % (base / 5 + 1)).min(300))
    }
}

pub(crate) fn can_fallback_after_udp(code: &str) -> bool {
    !matches!(
        code,
        "identity_mismatch"
            | "configuration_incomplete"
            | "identity_recovery_required"
            | "not_deployed"
            | "private_tcp_invalid_identity"
    )
}

pub(crate) fn error_code(message: &str) -> &'static str {
    match message {
        "identity_mismatch" => "identity_mismatch",
        "configuration_incomplete" => "configuration_incomplete",
        "identity_recovery_required" => "identity_recovery_required",
        "not_deployed" => "not_deployed",
        "udp_unavailable" => "udp_unavailable",
        "server_tcp_unsupported" => "server_tcp_unsupported",
        "private_tcp_invalid_identity" => "private_tcp_invalid_identity",
        "private_tcp_server_identity_mismatch" => "private_tcp_server_identity_mismatch",
        "private_tcp_invalid_frame" => "private_tcp_invalid_frame",
        "private_tcp_unencrypted_message" => "private_tcp_unencrypted_message",
        "private_tcp_device_proof_invalid" => "private_tcp_device_proof_invalid",
        "private_tcp_registration_failed" => "private_tcp_registration_failed",
        "private_tcp_invalid_challenge" => "private_tcp_invalid_challenge",
        "private_tcp_unexpected_registration" => "private_tcp_unexpected_registration",
        "private_tcp_key_exchange_failed" => "private_tcp_key_exchange_failed",
        "private_tcp_unsupported_version" => "private_tcp_unsupported_version",
        "private_tcp_transport_mismatch" => "private_tcp_transport_mismatch",
        "private_tcp_handshake_timeout" => "private_tcp_handshake_timeout",
        "private_tcp_heartbeat_timeout" => "private_tcp_heartbeat_timeout",
        "private_tcp_connection_lost" => "private_tcp_connection_lost",
        _ => "network_unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn udp_probe_has_a_bounded_initial_registration_deadline() {
        let now = Instant::now();
        let probe = UdpProbe::new(now);
        assert!(!probe.expired(now + Duration::from_secs(11)));
        assert!(probe.expired(now + Duration::from_secs(12)));
    }

    #[test]
    fn only_accepted_registration_extends_udp_deadline() {
        let now = Instant::now();
        let mut probe = UdpProbe::new(now);
        probe.accepted(now + Duration::from_secs(10));
        assert!(!probe.expired(now + Duration::from_secs(21)));
        assert!(probe.expired(now + Duration::from_secs(22)));
        assert!(probe.expired(now));
    }

    #[test]
    fn unsolicited_udp_heartbeats_cannot_create_registration_or_extend_probe() {
        let start = Instant::now();
        let mut probe = UdpProbe::new(start);
        probe.heartbeat(start + Duration::from_secs(10));
        assert!(probe.expired(start + Duration::from_secs(12)));
        probe.accepted(start + Duration::from_secs(20));
        probe.heartbeat(start + Duration::from_secs(25));
        assert!(!probe.expired(start + Duration::from_secs(36)));
        probe.require_registration(start + Duration::from_secs(30));
        probe.require_registration(start + Duration::from_secs(40));
        probe.heartbeat(start + Duration::from_secs(41));
        assert!(probe.expired(start + Duration::from_secs(42)));
    }

    #[test]
    fn retry_backoff_is_exponential_and_capped() {
        let mut policy = RetryPolicy::default();
        for seconds in [2, 4, 8, 16, 32, 64, 128, 256, 300, 300] {
            assert_eq!(policy.delay(0), Duration::from_secs(seconds));
        }
        for _ in 0..1000 {
            assert!(policy.delay(u32::MAX) <= Duration::from_secs(300));
        }
    }

    #[test]
    fn verified_tcp_preference_survives_disconnect_and_backoff_reset() {
        let mut policy = RetryPolicy::default();
        assert!(policy.should_probe_udp());
        policy.prefer_tcp();
        policy.record_error("network_unavailable");
        policy.reset_backoff();
        assert!(!policy.should_probe_udp());
        assert_eq!(policy.delay(0), Duration::from_secs(2));
    }

    #[test]
    fn crypto_errors_never_trigger_an_unverified_downgrade() {
        for error in [
            "private_tcp_server_identity_mismatch",
            "private_tcp_invalid_frame",
            "private_tcp_unencrypted_message",
            "private_tcp_device_proof_invalid",
            "private_tcp_registration_failed",
            "private_tcp_invalid_challenge",
        ] {
            let mut policy = RetryPolicy::default();
            policy.record_error(error);
            assert!(!policy.should_probe_udp(), "{}", error);
        }
    }

    #[test]
    fn identity_configuration_and_deployment_denials_are_not_bypassed() {
        for code in [
            "identity_mismatch",
            "configuration_incomplete",
            "identity_recovery_required",
            "not_deployed",
        ] {
            assert!(!can_fallback_after_udp(code), "{}", code);
        }
        assert!(can_fallback_after_udp("udp_unavailable"));
        assert!(can_fallback_after_udp("network_unavailable"));
    }

    #[test]
    fn authenticated_tcp_ownership_denial_cannot_be_bypassed_via_legacy_udp() {
        let mut udp_denial = RetryPolicy::default();
        udp_denial.record_error("identity_mismatch");
        assert!(udp_denial.should_probe_udp());
        let mut tcp_denial = RetryPolicy::default();
        tcp_denial.record_tcp_error("identity_mismatch");
        assert!(!tcp_denial.should_probe_udp());
    }

    #[test]
    fn legacy_capability_failure_does_not_lock_out_udp_recovery() {
        let mut policy = RetryPolicy::default();
        policy.record_error("server_tcp_unsupported");
        assert!(policy.should_probe_udp());
        assert!(policy.delay(0) >= Duration::from_secs(2));
    }

    #[test]
    fn unexpected_errors_are_redacted_to_stable_codes() {
        assert_eq!(error_code("identity_mismatch"), "identity_mismatch");
        assert_eq!(
            error_code("private_tcp_invalid_frame"),
            "private_tcp_invalid_frame"
        );
        assert_eq!(
            error_code("secret in a third-party error"),
            "network_unavailable"
        );
    }

    #[test]
    fn tcp_acknowledgement_deadline_is_independent_of_notifications() {
        let start = Instant::now();
        assert!(!acknowledgement_expired(
            start,
            start + Duration::from_secs(29),
            Duration::from_secs(30)
        ));
        assert!(acknowledgement_expired(
            start,
            start + Duration::from_secs(30),
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn architecture_native_private_recovery_is_wired_and_uses_accepted_udp_acknowledgements() {
        let source = include_str!("../rendezvous_mediator.rs");
        assert!(source.contains("Self::start_private(server, host).await"));
        assert!(source.contains("private_udp_probe"));
        assert!(source.matches("self.private_udp_probe.as_mut()").count() >= 2);
        assert!(source.contains("bail!(\"identity_mismatch\")"));
        assert!(source.contains("bail!(\"not_deployed\")"));
    }
}
