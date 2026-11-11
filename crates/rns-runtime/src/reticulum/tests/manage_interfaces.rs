//! Attaching, detaching and reloading configured interfaces at run time, as
//! Python's `Reticulum._attach_interface`, `_detach_interface` and
//! `_reload_interface` do (Reticulum.py:850-920).
use super::*;

fn config_dir(config: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rns-manage-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config"), config).unwrap();
    dir
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn names(handle: &ReticulumHandle) -> Vec<String> {
    let mut names: Vec<String> = handle
        .interface_stats()
        .await
        .unwrap()
        .interfaces
        .into_iter()
        .map(|entry| entry.identity.map_or(entry.name, |i| i.short_name))
        .collect();
    names.sort();
    names
}

async fn wait_for(handle: &ReticulumHandle, want: &[&str]) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let got = names(handle).await;
        if got == want || tokio::time::Instant::now() >= deadline {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn manage_follows_upstream_results_and_removes_spawned_connections() {
    let (managed, disabled) = (free_port(), free_port());
    let dir = config_dir(&format!(
        "[reticulum]\n  share_instance = No\n\n[interfaces]\n  \
         [[Managed]]\n    type = TCPServerInterface\n    enabled = yes\n    \
         listen_ip = 127.0.0.1\n    listen_port = {managed}\n  \
         [[Disabled]]\n    type = TCPServerInterface\n    enabled = no\n    bootstrap_only = yes\n    \
         listen_ip = 127.0.0.1\n    listen_port = {disabled}\n"
    ));
    let handle = init(
        Some(dir.to_str().unwrap()),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
    )
    .await
    .unwrap();

    let _peer = tokio::net::TcpStream::connect(("127.0.0.1", managed))
        .await
        .unwrap();
    let with_client = wait_for(&handle, &["Client on Managed", "Managed"]).await;
    let attach_running = handle.attach_interface("Managed").await.unwrap();
    let attach_unknown = handle.attach_interface("Nope").await.unwrap();
    let detach_unknown = handle.detach_interface("Nope").await.unwrap();
    let reload_unknown = handle.reload_interface("Nope").await.unwrap();
    let detach = handle.detach_interface("Managed").await.unwrap();
    let after_detach = wait_for(&handle, &[]).await;
    // The listener task closes its socket just after the interface is gone.
    let mut managed_closed = false;
    for _ in 0..50 {
        managed_closed = tokio::net::TcpStream::connect(("127.0.0.1", managed))
            .await
            .is_err();
        if managed_closed {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let attach_disabled = handle.attach_interface("Disabled").await.unwrap();
    let reload = handle.reload_interface("Disabled").await.unwrap();
    let after_reload = wait_for(&handle, &["Disabled"]).await;
    let bootstrap = handle.discovery.bootstrap_interfaces.lock().await.clone();
    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(with_client, ["Client on Managed", "Managed"]);
    assert_eq!(attach_running, Some(false));
    assert_eq!(attach_unknown, None);
    assert_eq!(detach_unknown, None);
    assert_eq!(reload_unknown, None);
    assert_eq!(detach, Some(true));
    assert!(
        after_detach.is_empty(),
        "spawned connection survived: {after_detach:?}"
    );
    assert!(managed_closed, "the detached listener still accepts");
    assert_eq!(attach_disabled, Some(true));
    assert_eq!(reload, Some(true));
    assert_eq!(after_reload, ["Disabled"]);
    assert_eq!(
        bootstrap.len(),
        1,
        "an attached bootstrap-only interface is tracked once"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn management_disabled_refuses_every_operation() {
    let port = free_port();
    let dir = config_dir(&format!(
        "[reticulum]\n  share_instance = No\n  enable_interface_management = no\n\n\
         [interfaces]\n  [[Managed]]\n    type = TCPServerInterface\n    enabled = yes\n    \
         listen_ip = 127.0.0.1\n    listen_port = {port}\n"
    ));
    let handle = init(
        Some(dir.to_str().unwrap()),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let results = [
        handle.detach_interface("Managed").await.unwrap(),
        handle.attach_interface("Nope").await.unwrap(),
        handle.reload_interface("Managed").await.unwrap(),
    ];
    let still_running = names(&handle).await;
    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(results, [Some(false); 3]);
    assert_eq!(still_running, ["Managed"]);
}
