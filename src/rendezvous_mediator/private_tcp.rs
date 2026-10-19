use super::retry_policy::{
    acknowledgement_expired, can_fallback_after_udp, error_code, RetryPolicy,
};
use super::*;
use hbb_common::{
    private_tcp::{register_client, ClientHandshake},
    sodiumoxide::crypto::sign,
};

impl RendezvousMediator {
    pub(super) async fn start_private(server: ServerPtr, host: String) -> ResultType<()> {
        let host = check_port(&host, RENDEZVOUS_PORT);
        let mut policy = RetryPolicy::default();
        let mut last_error = None;
        loop {
            if SHOULD_EXIT.load(Ordering::SeqCst) {
                return Ok(());
            }
            let mut code = "network_unavailable";
            let mut try_tcp = true;
            if policy.should_probe_udp() && !Config::is_proxy() && !crate::is_udp_disabled() {
                Config::set_key_confirmed(false);
                let started = Instant::now();
                let result = Self::start_udp(server.clone(), host.clone()).await;
                if SHOULD_EXIT.load(Ordering::SeqCst) {
                    return Ok(());
                }
                code = result
                    .err()
                    .map(|error| error_code(&error.to_string()))
                    .unwrap_or("udp_unavailable");
                if started.elapsed() >= Duration::from_secs(45) {
                    policy.reset_backoff();
                }
                crate::private_provision::rejected(code);
                Config::update_latency(&host, -1);
                try_tcp = can_fallback_after_udp(code);
            }
            if try_tcp {
                let mut registered_at = None;
                let result =
                    Self::start_private_tcp(server.clone(), host.clone(), &mut registered_at).await;
                if SHOULD_EXIT.load(Ordering::SeqCst) {
                    return Ok(());
                }
                if let Some(registered_at) = registered_at {
                    policy.prefer_tcp();
                    last_error = None;
                    if registered_at.elapsed() >= Duration::from_secs(30) {
                        policy.reset_backoff();
                    }
                }
                code = result
                    .err()
                    .map(|error| error_code(&error.to_string()))
                    .unwrap_or("private_tcp_connection_lost");
                policy.record_tcp_error(code);
            }
            policy.record_error(code);
            crate::private_provision::rejected(code);
            Config::set_key_confirmed(false);
            Config::set_host_key_confirmed(&Self::get_host_prefix(&host), false);
            Config::update_latency(&host, -1);
            if last_error != Some(code) {
                log::warn!("private rendezvous offline: {code}");
                last_error = Some(code);
            }
            let delay = policy.delay(hbb_common::rand::random());
            let deadline = Instant::now() + delay;
            while Instant::now() < deadline {
                if SHOULD_EXIT.load(Ordering::SeqCst) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    async fn start_private_tcp(
        server: ServerPtr,
        host: String,
        registered_at: &mut Option<Instant>,
    ) -> ResultType<()> {
        ensure_private_registration_complete().await?;
        let identity = private_registration_identity()
            .await?
            .ok_or_else(|| anyhow::anyhow!("configuration_incomplete"))?;
        let pair = Config::get_key_pair();
        let device_key = sign::SecretKey::from_slice(&pair.0)
            .ok_or_else(|| anyhow::anyhow!("identity_recovery_required"))?;
        anyhow::ensure!(
            device_key.public_key().as_ref() == pair.1.as_slice(),
            "identity_recovery_required"
        );
        let pinned = crate::get_rs_pk(&crate::get_key(true).await)
            .ok_or_else(|| anyhow::anyhow!("configuration_incomplete"))?;
        let state = ClientHandshake::new(
            identity.actual_id.clone(),
            hbb_common::get_uuid(),
            &device_key.public_key(),
        )?;
        let started = Instant::now();
        let mut conn = connect_tcp(host.clone(), CONNECT_TIMEOUT).await?;
        let (mut cipher, keep_alive) = match &mut conn {
            Stream::Tcp(stream) => register_client(stream, state, &pinned, &device_key).await?,
            _ => bail!("server_tcp_unsupported"),
        };
        if SHOULD_EXIT.load(Ordering::SeqCst) {
            return Ok(());
        }
        let (current, persisted) =
            tokio::task::spawn_blocking(Config::private_binding_identity).await??;
        anyhow::ensure!(persisted && current == identity, "configuration_incomplete");
        let mut rz = Self {
            addr: conn.local_addr().into_target_addr()?,
            host: host.clone(),
            host_prefix: Self::get_host_prefix(&host),
            keep_alive: keep_alive.as_millis() as i32,
            private_identity: Some(identity),
            private_udp_probe: None,
            transport: "tcp",
        };
        Config::set_key_confirmed(true);
        Config::set_host_key_confirmed(&rz.host_prefix, true);
        Config::update_latency(&host, (started.elapsed().as_micros() as i64).max(1));
        crate::private_provision::accepted(&rz.private_identity, "tcp");
        *registered_at = Some(Instant::now());
        log::info!("private rendezvous registered over authenticated TCP");
        let mut last_acknowledged = Instant::now();
        let mut heartbeat =
            tokio::time::interval_at(tokio::time::Instant::now() + keep_alive, keep_alive);
        let mut check = tokio::time::interval(Duration::from_millis(500));
        loop {
            select! {
                _ = check.tick() => {
                    if SHOULD_EXIT.load(Ordering::SeqCst) { return Ok(()); }
                    if acknowledgement_expired(last_acknowledged, Instant::now(), Duration::from_secs(30)) {
                        bail!("private_tcp_heartbeat_timeout");
                    }
                }
                _ = heartbeat.tick() => {
                    let mut message = Message::new();
                    message.set_register_peer(RegisterPeer { id: rz.private_identity.as_ref()
                        .map(|identity| identity.actual_id.clone()).unwrap_or_default(), ..Default::default() });
                    let mut outer = Message::new();
                    outer.set_private_tcp_frame(cipher.seal(&message)?);
                    conn.send(&outer).await.map_err(|_| anyhow::anyhow!("private_tcp_connection_lost"))?;
                }
                incoming = conn.next() => {
                    let bytes = incoming.ok_or_else(|| anyhow::anyhow!("private_tcp_connection_lost"))?
                        .map_err(|_| anyhow::anyhow!("private_tcp_connection_lost"))?;
                    let envelope = Message::parse_from_bytes(&bytes)
                        .map_err(|_| anyhow::anyhow!("private_tcp_invalid_frame"))?;
                    let frame = match envelope.union {
                        Some(rendezvous_message::Union::PrivateTcpFrame(frame)) => frame,
                        _ => bail!("private_tcp_unencrypted_message"),
                    };
                    let message = cipher.open(&frame)?;
                    match message.union {
                        Some(rendezvous_message::Union::RegisterPeerResponse(response)) if !response.request_pk => {
                            last_acknowledged = Instant::now();
                            crate::private_provision::heartbeat(&rz.private_identity);
                        }
                        notification @ Some(rendezvous_message::Union::PunchHole(_)) |
                        notification @ Some(rendezvous_message::Union::RequestRelay(_)) => {
                            rz.handle_resp(notification, Sink::Stream(&mut conn), &server, &mut || {}).await?;
                        }
                        _ => bail!("private_tcp_unexpected_registration"),
                    }
                }
            }
        }
    }
}
