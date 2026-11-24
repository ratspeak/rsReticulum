//! `init_with_policy_holding`: held interfaces stay out of the run, in memory
//! only, whichever enable key their section uses.
use super::*;

#[tokio::test]
async fn held_interfaces_do_not_start_and_the_config_is_never_rewritten() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rns-held-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = |name: &str, key: &str| {
        format!(
            "[[{name}]]\ntype = TCPClientInterface\n{key} = Yes\ntarget_host = 127.0.0.1\ntarget_port = {port}\n"
        )
    };
    let config = format!(
        "[reticulum]\nshare_instance = No\nenable_transport = No\n\n[interfaces]\n{}{}{}",
        client("Kept", "enabled"),
        client("Held by enabled", "enabled"),
        client("Held by interface_enabled", "interface_enabled"),
    );
    std::fs::write(dir.join("config"), &config).unwrap();
    let _starting = crate::destination_stamper::test_settings::starting().await;
    let handle = super::super::init_with_policy_holding(
        Some(dir.to_str().unwrap()),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
        InitOptions::default(),
        rns_interface::rnode::RNodeStartupOptions::default(),
        crate::shared_instance::InstancePolicy::Standalone,
        &[
            "Held by enabled".to_string(),
            "Held by interface_enabled".to_string(),
            "Not configured".to_string(),
        ],
    )
    .await
    .expect("start-up with held interfaces");
    let names: Vec<String> = match handle
        .query_control_result(TransportQuery::GetInterfaceStats)
        .await
    {
        Ok(TransportQueryResponse::InterfaceStats(stats)) => {
            stats.into_iter().map(|entry| entry.name).collect()
        }
        other => panic!("interface stats: {other:?}"),
    };
    handle.shutdown_and_wait().await;
    assert_eq!(names, ["Kept"]);
    assert_eq!(std::fs::read_to_string(dir.join("config")).unwrap(), config);
    let _ = std::fs::remove_dir_all(dir);
}
