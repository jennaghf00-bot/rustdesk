use hbb_common::{
    anyhow,
    config::{
        provision::ProvisionRequest,
        registration::{IdentityContext, RegistrationTracker, ServiceReceipt},
        Config,
    },
    ResultType,
};
use std::{path::PathBuf, sync::Mutex, time::Instant};

lazy_static::lazy_static! {
    static ref REGISTRATION: Mutex<RegistrationTracker> = Mutex::new(RegistrationTracker::default());
}

pub const PROVISION_FILE: &str = "rustdesk-private-provision.json";

pub fn reset_registration() {
    REGISTRATION.lock().unwrap().reset();
}

pub fn accepted(identity: &Option<IdentityContext>, transport: &str) {
    if let Some(identity) = identity {
        REGISTRATION
            .lock()
            .unwrap()
            .accept(identity.clone(), transport, Instant::now());
    }
}

pub fn heartbeat(identity: &Option<IdentityContext>) {
    if let Some(identity) = identity {
        REGISTRATION
            .lock()
            .unwrap()
            .heartbeat(identity, Instant::now());
    }
}

pub fn rejected(code: &str) {
    REGISTRATION.lock().unwrap().reject(code);
}

pub fn receipt() -> ResultType<ServiceReceipt> {
    anyhow::ensure!(
        Config::private_service_identity_enabled() && crate::is_server(),
        "private_service_unavailable"
    );
    let (identity, persisted) = Config::private_binding_identity()?;
    Ok(REGISTRATION
        .lock()
        .unwrap()
        .receipt(&identity, persisted, Instant::now()))
}

pub fn apply(request: &ProvisionRequest) -> ResultType<ServiceReceipt> {
    anyhow::ensure!(crate::is_server(), "private_service_unavailable");
    match Config::apply_private_provision(request, false) {
        Ok(result) => {
            if result.changed {
                crate::RendezvousMediator::restart();
            }
            receipt()
        }
        Err(error) => {
            rejected("configuration_incomplete");
            Err(error)
        }
    }
}

pub fn initialize_installed_service() -> ResultType<()> {
    Config::prepare_private_identity()?;
    #[cfg(windows)]
    if crate::platform::is_cur_exe_the_installed() {
        let path = std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow::anyhow!("provision_path_invalid"))?
            .join(PROVISION_FILE);
        if path.exists() {
            validate_install_directory(
                path.parent()
                    .ok_or_else(|| anyhow::anyhow!("provision_path_invalid"))?,
            )?;
            anyhow::ensure!(
                !std::fs::symlink_metadata(&path)?.file_type().is_symlink(),
                "provision_path_invalid"
            );
            let content = std::fs::read_to_string(path)
                .map_err(|_| anyhow::anyhow!("provision_read_failed"))?;
            let request: ProvisionRequest = serde_json::from_str(&content)
                .map_err(|_| anyhow::anyhow!("provision_config_invalid"))?;
            // Only the protected installed sidecar is admin-authorized; IPC input never is.
            Config::apply_private_provision(&request, true)?;
        }
    }
    Ok(())
}

pub fn staged_path() -> ResultType<PathBuf> {
    Ok(Config::file()
        .parent()
        .ok_or_else(|| anyhow::anyhow!("provision_path_invalid"))?
        .join("rustdesk-private-install-provision.json"))
}

pub fn stage(request_json: &str, install_path: &str) -> ResultType<()> {
    #[cfg(windows)]
    validate_install_directory(std::path::Path::new(install_path))?;
    let request: ProvisionRequest = serde_json::from_str(request_json)
        .map_err(|_| anyhow::anyhow!("provision_config_invalid"))?;
    hbb_common::config::provision::validate(&request)?;
    let target = staged_path()?;
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("provision_path_invalid"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".private-provision-{}.tmp", uuid::Uuid::new_v4()));
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(serde_json::to_string(&request)?.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, target)?;
    Ok(())
}

#[cfg(windows)]
pub fn validate_install_directory(path: &std::path::Path) -> ResultType<()> {
    use std::{os::windows::fs::MetadataExt, path::Component};
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
    let raw = path.to_string_lossy();
    anyhow::ensure!(
        path.is_absolute()
            && !raw
                .chars()
                .any(|c| ['"', '%', '!', '\r', '\n'].contains(&c))
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir)),
        "provision_install_path_untrusted"
    );
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion")?;
    let roots: Vec<PathBuf> = ["ProgramFilesDir", "ProgramFilesDir (x86)"]
        .iter()
        .filter_map(|name| key.get_value::<String, _>(name).ok())
        .map(PathBuf::from)
        .collect();
    let normalized = raw.replace('/', "\\").to_lowercase();
    anyhow::ensure!(
        roots.iter().any(|root| {
            let prefix = root.to_string_lossy().trim_end_matches('\\').to_lowercase() + "\\";
            normalized.starts_with(&prefix) && normalized.len() > prefix.len()
        }),
        "provision_install_path_untrusted"
    );
    for ancestor in path.ancestors() {
        if let Ok(metadata) = std::fs::symlink_metadata(ancestor) {
            anyhow::ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "provision_install_path_untrusted"
            );
        }
    }
    Ok(())
}
