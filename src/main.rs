use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use keystore::{
    init_keystore,
    software::{NoEncryptor, SoftwareKeystore},
};
use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteClient, ArcAnisetteClient};
use plist::Dictionary;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use rustpush::findmy::{BeaconAccessory, FindMyClient, FindMyStateManager};
use rustpush::keychain::{KeychainClient, KeychainClientState};
use rustpush::{
    APSState, ActivationInfo, AppleAccount, DebugMeta, DebugMutex, DebugRwLock, LoginDelegate,
    OSConfig, PushError, RegisterMeta, TokenProvider, login_apple_delegates,
};
use rustpush::{
    cloudkit::{CloudKitClient, CloudKitState},
    findmy::FindMyState,
};

// ── Fake OSConfig (presents as iPhone to avoid NAS validation) ───────

struct FakeIOSConfig {
    device_uuid: String,
    serial: String,
    udid: String,
}

impl FakeIOSConfig {
    fn new() -> Self {
        FakeIOSConfig {
            device_uuid: uuid::Uuid::new_v4().to_string().to_uppercase(),
            serial: "F2LZN0FAKE00".to_string(),
            udid: format!("{:032X}", rand::random::<u128>()),
        }
    }
}

#[async_trait]
impl OSConfig for FakeIOSConfig {
    fn build_activation_info(&self, _csr: Vec<u8>) -> ActivationInfo {
        unreachable!("activation not needed for FindMy export")
    }

    fn get_activation_device(&self) -> String {
        "iPhone".to_string()
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        Err(PushError::BadMsg) // don't generate any validation data
    }

    fn get_protocol_version(&self) -> u32 {
        1640
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: "iPhone15,2".to_string(),
            os_version: "iPhone OS,17.4,21E219".to_string(),
            software_version: "21E219".to_string(),
        }
    }

    fn get_normal_ua(&self, item: &str) -> String {
        format!("{item} CFNetwork/1494.0.7 Darwin/23.4.0")
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!("<iPhone15,2> <iPhone OS;17.4;21E219> <{}>", for_item)
    }

    fn get_version_ua(&self) -> String {
        "[iPhone OS,17.4,21E219,iPhone15,2]".to_string()
    }

    fn get_device_name(&self) -> String {
        "iPhone".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.device_uuid.clone()
    }

    fn get_private_data(&self) -> Dictionary {
        Dictionary::new()
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: "17.4".to_string(),
            hardware_version: "iPhone15,2".to_string(),
            serial_number: self.serial.clone(),
        }
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
    }

    fn get_serial_number(&self) -> String {
        self.serial.clone()
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    fn get_aoskit_version(&self) -> String {
        "com.apple.AuthKit/1 (com.apple.akd/1.0)".to_string()
    }

    fn get_udid(&self) -> String {
        self.udid.clone()
    }
}

// ── Plist generation ────────────────────────────────────────────────────

fn accessory_to_plist(acc: &BeaconAccessory) -> plist::Value {
    let mut dict = Dictionary::new();

    dict.insert(
        "privateKey".to_string(),
        plist::Value::Data(acc.master_record.private_key.clone()),
    );
    dict.insert(
        "sharedSecret".to_string(),
        plist::Value::Data(acc.master_record.shared_secret.clone()),
    );
    if let Some(ref ss2) = acc.master_record.shared_secret_2 {
        dict.insert(
            "secondarySharedSecret".to_string(),
            plist::Value::Data(ss2.clone()),
        );
    }
    if let Some(ref slss) = acc.master_record.secure_locations_shared_secret {
        dict.insert(
            "secureLocationsSharedSecret".to_string(),
            plist::Value::Data(slss.clone()),
        );
    }
    dict.insert(
        "publicKey".to_string(),
        plist::Value::Data(acc.master_record.public_key.clone()),
    );
    dict.insert(
        "identifier".to_string(),
        plist::Value::String(acc.master_record.stable_identifier.clone()),
    );
    dict.insert(
        "model".to_string(),
        plist::Value::String(acc.master_record.model.clone()),
    );
    if let Some(pairing_date) = acc.master_record.pairing_date {
        dict.insert(
            "pairingDate".to_string(),
            plist::Value::Date(pairing_date.into()),
        );
    }
    dict.insert(
        "name".to_string(),
        plist::Value::String(acc.naming.name.clone()),
    );
    dict.insert(
        "emoji".to_string(),
        plist::Value::String(acc.naming.emoji.clone()),
    );

    plist::Value::Dictionary(dict)
}

// ── Password reading ────────────────────────────────────────────────────

fn read_password() -> String {
    if std::io::stdin().is_terminal() {
        let pass = disable_echo_read();
        eprintln!();
        pass
    } else {
        let mut pass = String::new();
        std::io::stdin().read_line(&mut pass).unwrap();
        pass.trim().to_string()
    }
}

#[cfg(unix)]
fn disable_echo_read() -> String {
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let mut termios: libc::termios = std::mem::zeroed();
        libc::tcgetattr(fd, &mut termios);
        let old = termios;
        termios.c_lflag &= !libc::ECHO;
        libc::tcsetattr(fd, libc::TCSANOW, &termios);
        let mut pass = String::new();
        std::io::stdin().read_line(&mut pass).unwrap();
        libc::tcsetattr(fd, libc::TCSANOW, &old);
        pass.trim().to_string()
    }
}

#[cfg(not(unix))]
fn disable_echo_read() -> String {
    let mut pass = String::new();
    std::io::stdin().read_line(&mut pass).unwrap();
    pass.trim().to_string()
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut apple_id = String::new();
    let mut anisette_url = "https://ani.sidestore.io".to_string();
    let mut output_dir = PathBuf::from("accessories");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--apple-id" => {
                i += 1;
                apple_id = args[i].clone();
            }
            "--anisette-url" => {
                i += 1;
                anisette_url = args[i].clone();
            }
            "--output-dir" => {
                i += 1;
                output_dir = PathBuf::from(&args[i]);
            }
            "--help" | "-h" => {
                eprintln!("Usage: export_findmy [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --apple-id <email>       Apple ID email");
                eprintln!(
                    "  --anisette-url <url>     Anisette server URL (default: https://ani.sidestore.io)"
                );
                eprintln!(
                    "  --output-dir <dir>       Output directory for plist files (default: accessories)"
                );
                eprintln!();
                eprintln!("WARNING: Output plist files contain private key material.");
                return Ok(());
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                return Ok(());
            }
        }
        i += 1;
    }

    if apple_id.is_empty() {
        eprint!("Apple ID: ");
        std::io::stdin().read_line(&mut apple_id)?;
        apple_id = apple_id.trim().to_string();
    }

    eprint!("Password: ");
    let password = read_password();

    let state_dir = PathBuf::from("state");
    std::fs::create_dir_all(&state_dir)?;
    std::fs::create_dir_all(&output_dir)?;

    let keystore_path = state_dir.join("keystore.plist");
    let keystore_path_for_update = keystore_path.clone();
    init_keystore(SoftwareKeystore {
        state: plist::from_file(&keystore_path).unwrap_or_default(),
        update_state: Box::new(move |state| {
            plist::to_file_xml(&keystore_path_for_update, state).unwrap();
        }),
        encryptor: NoEncryptor,
    });

    let config: Arc<dyn OSConfig> = Arc::new(FakeIOSConfig::new());

    // ── Step 1: Create anisette client ──────────────────────────────
    eprintln!("[1/7] Connecting to anisette server...");
    let anisette_config_path = state_dir.join("anisette_state");
    std::fs::create_dir_all(&anisette_config_path).ok();

    let login_info = config.get_gsa_config(&APSState::default(), false);

    let anisette_client: ArcAnisetteClient<RemoteAnisetteProviderV3> = Arc::new(Mutex::new(
        AnisetteClient::new(RemoteAnisetteProviderV3::new(
            anisette_url.clone(),
            login_info.clone(),
            anisette_config_path,
        )),
    ));

    // ── Step 2: Login to Apple ──────────────────────────────────────
    eprintln!("[2/7] Logging in to Apple ID...");
    let apple_id_clone = apple_id.clone();
    let password_hash: Vec<u8> = Sha256::digest(password.as_bytes()).to_vec();
    let appleid_closure = move || (apple_id_clone.clone(), password_hash.clone());
    let tfa_closure = || {
        eprint!("2FA code: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    };

    let account = AppleAccount::login(
        appleid_closure,
        tfa_closure,
        login_info,
        anisette_client.clone(),
    )
    .await?;

    let spd = account.spd.as_ref().expect("No SPD after login");
    let dsid = spd["DsPrsId"].as_unsigned_integer().unwrap().to_string();
    let adsid = spd["adsid"].as_string().unwrap().to_string();

    let id_path = state_dir.join("findmy.plist");
    if !id_path.exists() {
        let findmy = FindMyState::new(dsid.clone());
        std::fs::write(&id_path, findmy.encode()?)?;
    }

    eprintln!("  Logged in (dsid={})", dsid);

    // ── Step 3: Get MobileMe delegate ───────────────────────────────
    eprintln!("[3/7] Fetching MobileMe delegate...");
    let delegates =
        login_apple_delegates(&account, None, config.as_ref(), &[LoginDelegate::MobileMe]).await?;
    let mobileme = delegates.mobileme.expect("No MobileMe delegate returned");

    // println!("{:#?}", mobileme);

    // ── Step 4: Create CloudKit + Keychain clients ──────────────────
    eprintln!("[4/7] Setting up CloudKit & Keychain...");

    let keychain_state_path = state_dir.join("trustedpeers.plist");
    let keychain_state: KeychainClientState = if let Ok(state) =
        plist::from_file(&keychain_state_path)
    {
        state
    } else {
        let keychain_state_opt = KeychainClientState::new(dsid.clone(), adsid.clone(), &mobileme);
        let state = keychain_state_opt.unwrap_or_else(|| {
            eprintln!("  (could not determine escrow proxy URL; using default)");
            KeychainClientState::new_with_host(
                dsid.clone(),
                adsid.clone(),
                "https://escrowproxy.icloud.com:443".to_string(),
            )
        });
        plist::to_file_xml(&keychain_state_path, &state)?;
        state
    };

    let account_arc = Arc::new(DebugMutex::new(account));
    let token_provider = TokenProvider::new(account_arc.clone(), config.clone());

    let cloudkit_state_path = state_dir.join("cloudkit.plist");
    let cloudkit_state: CloudKitState = if let Ok(state) = plist::from_file(&cloudkit_state_path) {
        state
    } else {
        let state = CloudKitState::new(dsid.clone()).expect("Failed to create CloudKitState");
        plist::to_file_xml(&cloudkit_state_path, &state)?;
        state
    };
    let cloudkit = Arc::new(CloudKitClient {
        state: DebugRwLock::new(cloudkit_state),
        anisette: anisette_client.clone(),
        config: config.clone(),
        token_provider: token_provider.clone(),
    });

    let keychain = Arc::new(KeychainClient {
        anisette: anisette_client.clone(),
        token_provider: token_provider.clone(),
        state: DebugRwLock::new(keychain_state),
        config: config.clone(),
        update_state: Box::new(move |update| {
            plist::to_file_xml(&keychain_state_path, update).unwrap();
        }),
        container: tokio::sync::Mutex::new(None),
        security_container: tokio::sync::Mutex::new(None),
        client: cloudkit.clone(),
    });

    // ── Step 5: Join iCloud Keychain circle via escrow ────────────
    eprintln!("[5/7] Joining iCloud Keychain trust circle...");
    if keychain.is_in_clique().await {
        eprintln!("  Already in trust circle; skipping escrow join.");
    } else {
        let bottles = keychain.get_viable_bottles().await?;
        if bottles.is_empty() {
            return Err(
                "No escrow bottles found. Make sure you have another trusted device.".into(),
            );
        }
        eprintln!("  Found {} escrow bottle(s):", bottles.len());
        for (i, (_, meta)) in bottles.iter().enumerate() {
            let device_name = meta
                .client_metadata
                .as_dictionary()
                .and_then(|d| d.get("device_name"))
                .and_then(|v| v.as_string());
            if let Some(name) = device_name {
                eprintln!("    [{}] {} ({})", i, meta.serial, name);
            } else {
                eprintln!("    [{}] {}", i, meta.serial);
            }
        }
        let bottle_idx = if bottles.len() == 1 {
            0
        } else {
            eprint!("  Choose bottle [0]: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let idx = input.trim().parse::<usize>().unwrap_or(0);
            if idx >= bottles.len() {
                return Err(format!(
                    "Invalid bottle index {}. Must be 0-{}.",
                    idx,
                    bottles.len() - 1
                )
                .into());
            }
            idx
        };
        let (bottle, meta) = &bottles[bottle_idx];
        eprintln!("  Using escrow bottle from device: {}", meta.serial);
        eprint!("  Enter the passcode of that device: ");
        let passcode = read_password();

        keychain
            .join_clique_from_escrow(bottle, passcode.as_bytes(), b"findmy-export")
            .await?;
        eprintln!("  Joined keychain trust circle!");
    }

    // ── Step 6: Fetch BeaconStore records from CloudKit ─────────────
    eprintln!("[6/7] Fetching FindMy accessories from CloudKit...");

    let id_path = state_dir.join("findmy.plist");
    let state = std::fs::read(&id_path).unwrap();
    let findmy_client = FindMyClient::new(
        cloudkit.clone(),
        keychain.clone(),
        config.clone(),
        FindMyStateManager::new(
            &state,
            Box::new(move |state| std::fs::write(&id_path, state).unwrap()),
        ),
        token_provider.clone(),
        anisette_client.clone(),
    )
    .await
    .unwrap();

    findmy_client.sync_items(false).await.unwrap();
    let accessories = &findmy_client.state.state.lock().await.accessories;

    // ── Step 7: Write plist files ───────────────────────────────────
    eprintln!("[7/7] Writing plist files...");

    if accessories.is_empty() {
        eprintln!("  No accessories found!");
        return Ok(());
    }

    for acc in accessories.values() {
        let safe_name: String = acc
            .naming
            .name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let filename = format!("{}.plist", safe_name);
        let path = output_dir.join(&filename);

        let plist_val = accessory_to_plist(acc);
        plist::to_file_xml(&path, &plist_val)?;

        eprintln!(
            "  {} {} ({}) -> {}",
            acc.naming.emoji,
            acc.naming.name,
            acc.master_record.model,
            path.display()
        );
    }

    eprintln!();
    eprintln!(
        "Done! Exported {} accessory plist file(s) to {}",
        accessories.len(),
        output_dir.display()
    );

    Ok(())
}
