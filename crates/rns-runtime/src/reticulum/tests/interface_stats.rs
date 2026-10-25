//! Runtime wiring of Python-shaped interface stats and remote management.
use super::*;

fn config_dir(tag: &str, config: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rns-stats-{tag}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config"), config).unwrap();
    dir
}

async fn is_local_destination(handle: &ReticulumHandle, dest: [u8; 16]) -> bool {
    matches!(
        handle
            .query_transport(TransportQuery::GetNextHop { dest })
            .await,
        Some(TransportQueryResponse::HashResult(Some(_)))
    )
}

/// `rnstatus -R` and `rnpath -R` take the remote's transport identity hash
/// and derive `rnstransport.remote.management` from it (rnstatus.py:367-369),
/// because Python registers that destination on `Transport.identity`
/// (Transport.py:367-368).
#[tokio::test]
async fn remote_management_answers_on_the_transport_identity() {
    let dir = config_dir(
        "remote-management",
        "[reticulum]\n\
         share_instance = No\n\
         enable_transport = Yes\n\
         enable_remote_management = Yes\n\
         remote_management_allowed = 0123456789abcdef0123456789abcdef\n\
         \n\
         [interfaces]\n",
    );
    let handle = init(
        Some(dir.to_str().unwrap()),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
    )
    .await
    .unwrap();
    let expected = rns_identity::destination::Destination::hash_from_name_and_identity(
        "rnstransport.remote.management",
        Some(&handle.transport_identity.hash),
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut registered = false;
    while !registered && tokio::time::Instant::now() < deadline {
        registered = is_local_destination(&handle, expected).await;
        if !registered {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    handle.shutdown_and_wait().await;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        registered,
        "the management destination is keyed on the transport identity"
    );
}
