use super::HwCommands;
use std::path::PathBuf;

pub fn run(cmd: HwCommands) {
    match cmd {
        HwCommands::Detect => cmd_detect(),
        HwCommands::Provision {
            pin,
            nickname,
            output,
        } => {
            cmd_provision(pin, nickname, output);
        }
        HwCommands::List { dir } => cmd_list(dir),
        HwCommands::Info { hwid } => cmd_info(hwid),
        HwCommands::Verify { hwid } => cmd_verify(hwid),
        HwCommands::Test { hwid, pin } => cmd_test(hwid, pin),
    }
}

fn cmd_detect() {
    println!("Scanning for hardware tokens...\n");

    match rns_ratkey::detect::detect_devices() {
        Ok(devices) => {
            if devices.is_empty() {
                println!("No compatible hardware tokens found.");
                println!("\nSupported devices:");
                println!("  - YubiKey 5 (firmware 5.7.0+)");
                println!("  - Nitrokey 3");
                println!("\nOn Linux, ensure pcscd is running: sudo systemctl start pcscd");
            } else {
                println!("Found {} device(s):\n", devices.len());
                for (i, dev) in devices.iter().enumerate() {
                    println!("  {}. {} ({})", i + 1, dev.device_type, dev.reader_name);
                    if let Some(serial) = dev.serial {
                        println!("     Serial: {serial}");
                    }
                    if let Some(ref fw) = dev.firmware {
                        println!("     Firmware: {fw}");
                    }
                    println!(
                        "     Slot 9A (signing): {}",
                        if dev.has_signing_key {
                            "occupied"
                        } else {
                            "empty"
                        }
                    );
                    println!(
                        "     Slot 9D (encryption): {}",
                        if dev.has_encryption_key {
                            "occupied"
                        } else {
                            "empty"
                        }
                    );
                    println!();
                }
            }
        }
        Err(e) => {
            eprintln!("Error detecting devices: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_provision(pin: Option<String>, nickname: Option<String>, output: Option<PathBuf>) {
    let pin = match pin {
        Some(p) => p,
        None => {
            eprintln!("Error: --pin is required for provisioning");
            eprintln!("Usage: rnid-rs hw provision --pin <PIN> [--nickname <NAME>]");
            std::process::exit(1);
        }
    };

    if pin.len() < 6 || pin.len() > 8 {
        eprintln!("Error: PIN must be 6-8 characters");
        std::process::exit(1);
    }

    let mut session = match rns_ratkey::PcscPivSession::connect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error connecting to hardware token: {e}");
            eprintln!("\nRun `rnid-rs hw detect` to check for connected devices.");
            std::process::exit(1);
        }
    };

    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("PIN verification failed: {e}");
        std::process::exit(1);
    }

    // Slot 9A (PIV authentication). PIN-once + touch-never: the PIN is the
    // session unlock; the app re-locks on timeout / quit. (Policies are burned
    // in permanently for a hardware-only identity.)
    println!("Generating Ed25519 key in slot 9A...");
    let ed_pub = match session.generate_ed25519(
        rns_ratkey::apdu::SLOT_AUTHENTICATION,
        Some(rns_ratkey::apdu::PIN_POLICY_ONCE),
        Some(rns_ratkey::apdu::TOUCH_POLICY_NEVER),
    ) {
        Ok(pub_key) => pub_key,
        Err(e) => {
            eprintln!("Error generating Ed25519 key: {e}");
            std::process::exit(1);
        }
    };

    // Slot 9D (PIV key management). PIN-once + touch-never: ECDH runs on every
    // inbound packet, so per-op touch is impractical; the PIN gates the session.
    println!("Generating X25519 key in slot 9D...");
    let x_pub = match session.generate_x25519(
        rns_ratkey::apdu::SLOT_KEY_MANAGEMENT,
        Some(rns_ratkey::apdu::PIN_POLICY_ONCE),
        Some(rns_ratkey::apdu::TOUCH_POLICY_NEVER),
    ) {
        Ok(pub_key) => pub_key,
        Err(e) => {
            eprintln!("Error generating X25519 key: {e}");
            std::process::exit(1);
        }
    };

    let identity_hash = rns_ratkey::provision::compute_identity_hash(&ed_pub, &x_pub);
    let hash_hex = hex::encode(identity_hash);

    println!("\nHardware identity provisioned:");
    println!("  Identity hash:  {hash_hex}");
    println!("  Ed25519 public: {}", hex::encode(ed_pub));
    println!("  X25519 public:  {}", hex::encode(x_pub));
    println!("  Device:         {}", session.device_type().as_str());

    if let Some(dir) = output {
        let identity_dir = dir.join(&hash_hex);
        if let Err(e) = std::fs::create_dir_all(&identity_dir) {
            eprintln!("Error creating directory: {e}");
            std::process::exit(1);
        }
        let path = identity_dir.join("identity.hwid");

        let config = rns_ratkey::hwid::HwidConfig {
            identity: rns_ratkey::hwid::HwidIdentity {
                hash: hash_hex.clone(),
                nickname: nickname.unwrap_or_default(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
            device: rns_ratkey::hwid::HwidDevice {
                device_type: session.device_type().as_str().to_string(),
                serial: session.serial().unwrap_or(0),
                firmware: session.firmware().unwrap_or("unknown").to_string(),
            },
            keys: rns_ratkey::hwid::HwidKeys {
                ed25519_pub: hex::encode(ed_pub),
                x25519_pub: hex::encode(x_pub),
            },
            slots: rns_ratkey::hwid::HwidSlots {
                signing: "9A".to_string(),
                encryption: "9D".to_string(),
            },
            policy: rns_ratkey::hwid::HwidPolicy {
                pin_cache_timeout: 300,
                touch_signing: "never".to_string(),
                touch_encryption: "never".to_string(),
            },
            attestation: Default::default(),
            app: Default::default(),
            backup: Default::default(),
        };

        match config.to_file(&path) {
            Ok(()) => println!("  Saved to: {}", path.display()),
            Err(e) => eprintln!("  Warning: failed to write .hwid file: {e}"),
        }
    }

    println!("\nWARNING: No backup exists. If you lose this device, this identity");
    println!("is gone forever. Run `rnid-rs hw backup` to create a backup.");
}

fn cmd_list(dir: Option<PathBuf>) {
    let dir = dir.unwrap_or_else(|| {
        eprintln!("Error: --dir is required (directory containing identity folders)");
        std::process::exit(1);
    });

    if !dir.exists() {
        eprintln!("Directory does not exist: {}", dir.display());
        std::process::exit(1);
    }

    let mut found = 0;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let hwid_path = entry.path().join("identity.hwid");
            if hwid_path.exists() {
                match rns_ratkey::hwid::HwidConfig::from_file(&hwid_path) {
                    Ok(config) => {
                        found += 1;
                        println!(
                            "  {} ({}, {})",
                            config.identity.hash,
                            config.device.device_type,
                            if config.identity.nickname.is_empty() {
                                "unnamed"
                            } else {
                                &config.identity.nickname
                            }
                        );
                    }
                    Err(e) => {
                        eprintln!("  Error reading {}: {e}", hwid_path.display());
                    }
                }
            }
        }
    }

    if found == 0 {
        println!("No hardware identities found in {}", dir.display());
    } else {
        println!("\n{found} hardware identity(s) found.");
    }
}

fn cmd_info(hwid_path: PathBuf) {
    let config = match rns_ratkey::hwid::HwidConfig::from_file(&hwid_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading .hwid file: {e}");
            std::process::exit(1);
        }
    };

    println!("Hardware Identity Information:");
    println!("  Hash:            {}", config.identity.hash);
    println!(
        "  Nickname:        {}",
        if config.identity.nickname.is_empty() {
            "(none)"
        } else {
            &config.identity.nickname
        }
    );
    println!(
        "  Created:         {} (Unix timestamp)",
        config.identity.created_at
    );
    println!();
    println!("Device:");
    println!("  Type:            {}", config.device.device_type);
    println!("  Serial:          {}", config.device.serial);
    println!("  Firmware:        {}", config.device.firmware);
    println!();
    println!("Keys:");
    println!("  Ed25519 public:  {}", config.keys.ed25519_pub);
    println!("  X25519 public:   {}", config.keys.x25519_pub);
    println!();
    println!("Slots:");
    println!("  Signing:         {}", config.slots.signing);
    println!("  Encryption:      {}", config.slots.encryption);
    println!();
    println!("Policy:");
    println!("  PIN cache:       {}s", config.policy.pin_cache_timeout);
    println!("  Touch (sign):    {}", config.policy.touch_signing);
    println!("  Touch (encrypt): {}", config.policy.touch_encryption);
    println!();
    println!("Backup:");
    println!("  Tier:            {}", config.backup.tier);
    if !config.attestation.ed25519_cert.is_empty() {
        println!(
            "  Attestation:     chain_verified={}",
            config.attestation.verified
        );
    } else {
        println!("  Attestation:     (none)");
    }
}

fn cmd_verify(hwid_path: PathBuf) {
    let config = match rns_ratkey::hwid::HwidConfig::from_file(&hwid_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading .hwid file: {e}");
            std::process::exit(1);
        }
    };

    println!("Verifying hardware identity {}...", config.identity.hash);

    let expected_ed = match config.ed25519_pub_bytes() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: .hwid has invalid Ed25519 key: {e}");
            std::process::exit(1);
        }
    };
    let expected_x = match config.x25519_pub_bytes() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error: .hwid has invalid X25519 key: {e}");
            std::process::exit(1);
        }
    };

    let mut session = match rns_ratkey::PcscPivSession::connect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: cannot connect to hardware token: {e}");
            std::process::exit(1);
        }
    };

    // Reads the slot public keys from GET METADATA and compares against the .hwid.
    // This is the on-device confirmation of the metadata parser before it gates
    // HardwareIdentity construction.
    let mut ok = true;
    match session.read_public_key(rns_ratkey::apdu::SLOT_AUTHENTICATION) {
        Ok(dev_ed) if dev_ed == expected_ed => println!("  Slot 9A (Ed25519): MATCH"),
        Ok(_) => {
            println!("  Slot 9A (Ed25519): MISMATCH");
            ok = false;
        }
        Err(e) => {
            println!("  Slot 9A (Ed25519): error reading key: {e}");
            ok = false;
        }
    }
    match session.read_public_key(rns_ratkey::apdu::SLOT_KEY_MANAGEMENT) {
        Ok(dev_x) if dev_x == expected_x => println!("  Slot 9D (X25519): MATCH"),
        Ok(_) => {
            println!("  Slot 9D (X25519): MISMATCH");
            ok = false;
        }
        Err(e) => {
            println!("  Slot 9D (X25519): error reading key: {e}");
            ok = false;
        }
    }

    if ok {
        println!("\nVerified: connected token matches this .hwid.");
    } else {
        println!("\nVerification FAILED: token does not match this .hwid.");
        std::process::exit(1);
    }
}

fn cmd_test(hwid_path: PathBuf, pin: Option<String>) {
    let config = match rns_ratkey::hwid::HwidConfig::from_file(&hwid_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading .hwid file: {e}");
            std::process::exit(1);
        }
    };

    let pin = match pin {
        Some(p) => p,
        None => {
            eprintln!("Error: --pin is required (PIN-once keys need one verification per session)");
            eprintln!("Usage: rnid-rs hw test <hwid> --pin <PIN>");
            std::process::exit(1);
        }
    };

    println!("Testing hardware identity {}...\n", config.identity.hash);

    let mut session = match rns_ratkey::PcscPivSession::connect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: cannot connect to hardware token: {e}");
            std::process::exit(1);
        }
    };

    // PIN_POLICY_ONCE: a fresh session must verify the PIN before any private-key op.
    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("PIN verification failed: {e}");
        std::process::exit(1);
    }

    println!("1. Testing Ed25519 signing in slot 9A...");
    let test_msg = b"RATKEY hardware identity test message";
    match session.sign_ed25519(rns_ratkey::apdu::SLOT_AUTHENTICATION, test_msg) {
        Ok(sig) => {
            let ed_pub = config.ed25519_pub_bytes().unwrap();
            let pub_key = rns_crypto::ed25519::Ed25519PublicKey::from_bytes(&ed_pub).unwrap();
            if pub_key.verify(test_msg, &sig).is_ok() {
                println!("   PASS: signature verified");
            } else {
                println!("   FAIL: signature verification failed");
                std::process::exit(1);
            }
        }
        Err(e) => {
            println!("   FAIL: {e}");
            std::process::exit(1);
        }
    }

    println!("2. Testing X25519 ECDH in slot 9D...");
    let peer_prv = rns_crypto::x25519::X25519PrivateKey::generate();
    let peer_pub = peer_prv.public_key().to_bytes();
    match session.ecdh_x25519(rns_ratkey::apdu::SLOT_KEY_MANAGEMENT, &peer_pub) {
        Ok(shared) => {
            println!("   PASS: ECDH returned {} bytes", shared.len());
            let hw_pub_bytes = config.x25519_pub_bytes().unwrap();
            let hw_pub = rns_crypto::x25519::X25519PublicKey::from_bytes(&hw_pub_bytes);
            let peer_shared = peer_prv.exchange(&hw_pub);
            if shared == peer_shared {
                println!("   PASS: ECDH is symmetric");
            } else {
                println!("   FAIL: ECDH shared secrets do not match");
                std::process::exit(1);
            }
        }
        Err(e) => {
            println!("   FAIL: {e}");
            std::process::exit(1);
        }
    }

    println!("3. Testing HardwareIdentity decrypt (on-device ECDH + HKDF + AES) end-to-end...");
    let mut hw = match rns_ratkey::HardwareIdentity::from_hwid(config.clone(), Box::new(session)) {
        Ok(h) => h,
        Err(e) => {
            println!("   FAIL: cannot build HardwareIdentity: {e}");
            std::process::exit(1);
        }
    };
    let plaintext = b"RATKEY end-to-end decrypt test";
    let ciphertext = match hw.as_identity().encrypt(plaintext, None) {
        Ok(c) => c,
        Err(e) => {
            println!("   FAIL: encrypt to hardware identity failed: {e}");
            std::process::exit(1);
        }
    };
    match hw.decrypt(&ciphertext, None, false) {
        Ok(pt) if pt == plaintext => println!("   PASS: round-trip decrypt via on-device ECDH"),
        Ok(_) => {
            println!("   FAIL: decrypted plaintext mismatch");
            std::process::exit(1);
        }
        Err(e) => {
            println!("   FAIL: {e}");
            std::process::exit(1);
        }
    }

    println!("\nAll tests passed.");
}
