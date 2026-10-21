use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::{secretbox, sign};
use std::{
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
pub type Result<T> = std::result::Result<T, &'static str>;
pub const DLL_HASH: &str = "325f8178e27472918ed9dab2e886f6bbd13dbebac7087fdfc6e26e3553ade449";
pub const ARCHIVE_HASH: &str = "cb22547a85aa2f0c21a44cb524edb1c6c5705655897e0edf66c2ff34c93c7247";
pub struct Baseline {
    pub id: String,
    pub fingerprint: String,
    provision_hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Provision {
    remote_id: String,
    unattended_password: String,
    #[serde(default)]
    settings_password: String,
    hbbs_address: String,
    hbbr_address: String,
    server_key: String,
}
pub fn bytes_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn file_hash(path: &Path) -> Result<String> {
    safe_path(path)?;
    let mut f = fs::File::open(path).map_err(|_| "file_read_failed")?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).map_err(|_| "file_read_failed")?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn text(path: &Path) -> Result<String> {
    safe_path(path)?;
    if fs::metadata(path)
        .map_err(|_| "configuration_missing")?
        .len()
        > 1024 * 1024
    {
        return Err("configuration_too_large");
    }
    fs::read_to_string(path).map_err(|_| "configuration_read_failed")
}
fn table(path: &Path) -> Result<toml::Value> {
    toml::from_str(&text(path)?).map_err(|_| "configuration_invalid")
}
fn string<'a>(v: &'a toml::Value, key: &str) -> &'a str {
    v.get(key).and_then(toml::Value::as_str).unwrap_or("")
}
fn option<'a>(v: &'a toml::Value, key: &str) -> &'a str {
    v.get("options").map(|v| string(v, key)).unwrap_or("")
}
fn decoded(value: &str, machine: &[u8], pk: &[u8]) -> Result<String> {
    if let Some(encoded) = value.strip_prefix("00") {
        if let Ok(data) = STANDARD.decode(encoded) {
            for source in [machine, pk] {
                let mut key = source.to_vec();
                key.resize(32, 0);
                if let Ok(clear) = secretbox::open(
                    &data,
                    &secretbox::Nonce([0; 24]),
                    &secretbox::Key::from_slice(&key).ok_or("identity_invalid")?,
                ) {
                    return String::from_utf8(clear).map_err(|_| "identity_invalid");
                }
            }
        }
        return Err("encrypted_configuration_unreadable");
    }
    Ok(value.to_owned())
}
pub fn baseline(provision: &Path, config: &Path, machine: &[u8]) -> Result<Baseline> {
    sodiumoxide::init().map_err(|_| "crypto_unavailable")?;
    let raw = text(provision)?;
    let p: Provision = serde_json::from_str(&raw).map_err(|_| "provision_invalid")?;
    if p.remote_id.is_empty()
        || p.remote_id.len() > 128
        || p.remote_id.chars().any(char::is_control)
        || p.unattended_password.is_empty()
    {
        return Err("provision_invalid");
    }
    let main = table(&config.join("RustDesk.toml"))?;
    let local = table(&config.join("RustDesk_local.toml"))?;
    let options = table(&config.join("RustDesk2.toml"))?;
    let (sk, pk): (Vec<u8>, Vec<u8>) = main
        .get("key_pair")
        .ok_or("identity_missing")?
        .clone()
        .try_into()
        .map_err(|_| "identity_invalid")?;
    let secret = sign::SecretKey::from_slice(&sk).ok_or("identity_invalid")?;
    let public = sign::PublicKey::from_slice(&pk).ok_or("identity_invalid")?;
    let proof = sign::sign_detached(b"RustDesk maintenance identity validation v1", &secret);
    if !sign::verify_detached(
        &proof,
        b"RustDesk maintenance identity validation v1",
        &public,
    ) {
        return Err("identity_invalid");
    }
    let raw_id = if !string(&main, "enc_id").is_empty() {
        decoded(string(&main, "enc_id"), machine, &pk)?
    } else {
        string(&main, "id").to_owned()
    };
    if raw_id != p.remote_id || option(&local, "private-forced-remote-id") != p.remote_id {
        return Err("identity_conflict");
    }
    let salt = string(&main, "salt");
    if salt.is_empty() {
        return Err("password_conflict");
    }
    let expected = format!(
        "01{}",
        STANDARD.encode(Sha256::digest(
            [p.unattended_password.as_bytes(), salt.as_bytes()].concat()
        ))
    );
    let stored = string(&main, "password");
    let actual = if stored == p.unattended_password {
        stored.to_owned()
    } else {
        decoded(stored, machine, &pk).map_err(|_| "password_conflict")?
    };
    if actual != expected && actual != p.unattended_password {
        return Err("password_conflict");
    }
    if decoded(option(&local, "private-settings-password"), machine, &pk)
        .map_err(|_| "settings_password_conflict")?
        != p.settings_password
    {
        return Err("settings_password_conflict");
    }
    for (key, expected) in [
        ("custom-rendezvous-server", p.hbbs_address),
        ("relay-server", p.hbbr_address),
        ("key", p.server_key),
    ] {
        if option(&options, key) != expected {
            return Err("server_configuration_conflict");
        }
    }
    Ok(Baseline {
        id: p.remote_id,
        fingerprint: STANDARD.encode(Sha256::digest(pk)),
        provision_hash: bytes_hash(raw.as_bytes()),
    })
}
pub fn same_identity(before: &Baseline, after: &Baseline) -> Result<()> {
    if before.id != after.id
        || before.fingerprint != after.fingerprint
        || before.provision_hash != after.provision_hash
    {
        return Err("identity_changed");
    }
    Ok(())
}
pub fn receipt(b: &Baseline, raw: &str) -> Result<bool> {
    let r: serde_json::Value = serde_json::from_str(raw.trim()).map_err(|_| "receipt_invalid")?;
    if r["version"] != 1 || r["actualId"] != b.id || r["publicFingerprint"] != b.fingerprint {
        return Err("receipt_identity_changed");
    }
    if r["persisted"] != true || r["generation"].as_str().unwrap_or("").is_empty() {
        return Err("identity_not_persisted");
    }
    if !r["errorCode"].is_null() {
        return Err("registration_rejected");
    }
    r["registered"].as_bool().ok_or("receipt_invalid")
}
pub fn relative(raw: &str) -> Result<PathBuf> {
    let normalized = raw.replace('\\', "/");
    let raw = normalized.strip_prefix("./").unwrap_or(&normalized);
    if raw.is_empty()
        || raw.contains(':')
        || raw
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.ends_with('.') || p.ends_with(' '))
    {
        return Err("unsafe_relative_path");
    }
    let path = PathBuf::from(&raw);
    if path
        .components()
        .any(|p| !matches!(p, Component::Normal(_)))
    {
        return Err("unsafe_relative_path");
    }
    Ok(path)
}
pub fn safe_path(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.components().any(|p| matches!(p, Component::ParentDir)) {
        return Err("unsafe_path");
    }
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err("reparse_path");
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x400 != 0 {
                        return Err("reparse_path");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("path_unreadable"),
        }
    }
    Ok(())
}
pub fn tree(root: &Path) -> Result<Vec<PathBuf>> {
    safe_path(root)?;
    let mut result = vec![root.to_owned()];
    let mut i = 0;
    while i < result.len() {
        let path = result[i].clone();
        if fs::metadata(&path)
            .map_err(|_| "tree_read_failed")?
            .is_dir()
        {
            for e in fs::read_dir(&path).map_err(|_| "tree_read_failed")? {
                let path = e.map_err(|_| "tree_read_failed")?.path();
                safe_path(&path)?;
                result.push(path);
                if result.len() > 20000 {
                    return Err("snapshot_too_large");
                }
            }
        }
        i += 1;
    }
    Ok(result)
}
pub trait Security {
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    fn restore(&self, path: &Path, value: &[u8]) -> Result<()>;
}
#[derive(Serialize)]
struct Saved {
    root: usize,
    relative: PathBuf,
    directory: bool,
    sha256: String,
    security: Vec<u8>,
    readonly: bool,
}
#[derive(Serialize)]
pub struct Snapshot {
    roots: Vec<PathBuf>,
    entries: Vec<Saved>,
    backup: PathBuf,
}
pub fn writable(path: &Path) -> Result<()> {
    let mut p = fs::metadata(path)
        .map_err(|_| "file_metadata_failed")?
        .permissions();
    if p.readonly() {
        p.set_readonly(false);
        fs::set_permissions(path, p).map_err(|_| "file_permissions_failed")?;
    }
    Ok(())
}
impl Snapshot {
    pub fn capture(roots: &[PathBuf], backup: &Path, security: &dyn Security) -> Result<Self> {
        safe_path(backup)?;
        if roots.iter().any(|root| backup.starts_with(root)) {
            return Err("unsafe_backup_location");
        }
        let mut s = Self {
            roots: roots.to_vec(),
            entries: vec![],
            backup: backup.to_owned(),
        };
        let mut total = 0u64;
        for (index, root) in roots.iter().enumerate() {
            for path in tree(root)? {
                let meta = fs::metadata(&path).map_err(|_| "snapshot_failed")?;
                let mut e = Saved {
                    root: index,
                    relative: path
                        .strip_prefix(root)
                        .map_err(|_| "unsafe_path")?
                        .to_owned(),
                    directory: meta.is_dir(),
                    sha256: String::new(),
                    security: security.read(&path)?,
                    readonly: meta.permissions().readonly(),
                };
                if !e.directory {
                    total = total.checked_add(meta.len()).ok_or("snapshot_too_large")?;
                    if total > 2 * 1024 * 1024 * 1024 {
                        return Err("snapshot_too_large");
                    }
                    e.sha256 = file_hash(&path)?;
                    let copy = backup.join(s.entries.len().to_string());
                    fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&copy)
                        .map_err(|_| "snapshot_failed")?;
                    fs::copy(&path, &copy).map_err(|_| "snapshot_failed")?;
                    if file_hash(&copy)? != e.sha256 || file_hash(&path)? != e.sha256 {
                        return Err("snapshot_inconsistent");
                    }
                    writable(&copy)?;
                    fs::OpenOptions::new()
                        .write(true)
                        .open(&copy)
                        .and_then(|f| f.sync_all())
                        .map_err(|_| "snapshot_flush_failed")?;
                }
                s.entries.push(e);
            }
        }
        let bytes = serde_json::to_vec(&s).map_err(|_| "snapshot_failed")?;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(backup.join("snapshot.json"))
            .map_err(|_| "snapshot_failed")?;
        f.write_all(&bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| "snapshot_failed")?;
        Ok(s)
    }
    pub fn restore(&self, security: &dyn Security) -> Result<()> {
        for (i, e) in self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.directory)
        {
            if file_hash(&self.backup.join(i.to_string()))? != e.sha256 {
                return Err("backup_checksum_failed");
            }
        }
        for (index, root) in self.roots.iter().enumerate() {
            let mut current = tree(root)?;
            current.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
            for path in current {
                let rel = path.strip_prefix(root).map_err(|_| "unsafe_path")?;
                if !self
                    .entries
                    .iter()
                    .any(|e| e.root == index && e.relative == rel)
                {
                    if path.is_dir() {
                        fs::remove_dir(&path).map_err(|_| "rollback_failed")?;
                    } else {
                        writable(&path)?;
                        fs::remove_file(&path).map_err(|_| "rollback_failed")?;
                    }
                }
            }
        }
        for (i, e) in self.entries.iter().enumerate() {
            let path = self.roots[e.root].join(&e.relative);
            safe_path(&path)?;
            if e.directory {
                fs::create_dir_all(&path).map_err(|_| "rollback_failed")?;
            } else {
                if path.exists() {
                    writable(&path)?;
                }
                fs::copy(self.backup.join(i.to_string()), &path).map_err(|_| "rollback_failed")?;
                if file_hash(&path)? != e.sha256 {
                    return Err("rollback_checksum_failed");
                }
            }
        }
        for e in self.entries.iter().rev() {
            let path = self.roots[e.root].join(&e.relative);
            security.restore(&path, &e.security)?;
            let mut p = fs::metadata(&path)
                .map_err(|_| "rollback_failed")?
                .permissions();
            p.set_readonly(e.readonly);
            fs::set_permissions(&path, p).map_err(|_| "rollback_failed")?;
        }
        Ok(())
    }
}
pub struct Target {
    pub install: PathBuf,
    pub config: PathBuf,
    pub provision: PathBuf,
    pub machine: Vec<u8>,
}
pub struct ServiceRecord {
    pub name: String,
    pub exe: PathBuf,
    pub args: Vec<String>,
    pub account: String,
    pub start: u32,
}
pub fn validate_install(
    records: &[ServiceRecord],
    install: &Path,
    roots: &[PathBuf],
) -> Result<()> {
    if records.len() != 1 {
        return Err("service_ambiguous_or_missing");
    }
    let r = &records[0];
    if !r.name.eq_ignore_ascii_case("RustDesk") {
        return Err("unsupported_brand");
    }
    if !["localsystem", "nt authority\\localservice"]
        .contains(&r.account.to_ascii_lowercase().as_str())
    {
        return Err("unsupported_account");
    }
    safe_path(install)?;
    safe_path(&r.exe)?;
    if !roots
        .iter()
        .any(|root| install.starts_with(root) && install != root)
        || r.exe.parent() != Some(install)
        || !r
            .exe
            .file_name()
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case("rustdesk.exe"))
            .unwrap_or(false)
        || r.args != ["--service"]
        || r.start != 2
    {
        return Err("untrusted_installation");
    }
    Ok(())
}
pub struct Payload {
    pub stage: PathBuf,
    pub files: Vec<(PathBuf, String)>,
}
pub trait Runtime {
    fn stop(&mut self) -> Result<()>;
    fn start(&mut self) -> Result<()>;
    fn restore_original_state(&mut self) -> Result<()>;
    fn read_receipt(&mut self) -> Result<String>;
}
#[derive(Debug, Serialize)]
pub struct Outcome {
    pub status: &'static str,
    pub error: Option<&'static str>,
    pub rollback_error: Option<&'static str>,
}
impl Outcome {
    fn new(status: &'static str, error: Option<&'static str>) -> Self {
        Self {
            status,
            error,
            rollback_error: None,
        }
    }
}
impl Payload {
    pub fn verify(&self, root: &Path) -> Result<()> {
        if self.files.is_empty() {
            return Err("payload_empty");
        }
        for (path, hash) in &self.files {
            if relative(&path.to_string_lossy())? != *path {
                return Err("unsafe_relative_path");
            }
            if file_hash(&root.join(path))? != *hash {
                return Err("payload_checksum_failed");
            }
        }
        Ok(())
    }
    fn copy_to(&self, root: &Path, security: &dyn Security) -> Result<()> {
        for (path, hash) in &self.files {
            let source = self.stage.join(path);
            let dest = root.join(path);
            safe_path(&dest)?;
            if file_hash(&source)? != *hash {
                return Err("payload_checksum_failed");
            }
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|_| "file_copy_failed")?;
            }
            let acl = security.read(if dest.exists() {
                &dest
            } else {
                dest.parent().ok_or("unsafe_path")?
            })?;
            let original_readonly = dest
                .metadata()
                .ok()
                .map(|m| m.permissions().readonly())
                .unwrap_or(false);
            if dest.is_file() {
                writable(&dest)?;
            }
            fs::copy(&source, &dest).map_err(|_| "file_copy_failed")?;
            security.restore(&dest, &acl)?;
            fs::OpenOptions::new()
                .write(true)
                .open(&dest)
                .and_then(|f| f.sync_all())
                .map_err(|_| "file_flush_failed")?;
            if file_hash(&dest)? != *hash {
                return Err("installed_checksum_failed");
            }
            if original_readonly {
                let mut permissions = fs::metadata(&dest)
                    .map_err(|_| "file_metadata_failed")?
                    .permissions();
                permissions.set_readonly(true);
                fs::set_permissions(&dest, permissions).map_err(|_| "file_permissions_failed")?;
            }
        }
        Ok(())
    }
}
pub fn upgrade(
    t: &Target,
    p: &Payload,
    b: &Baseline,
    backup: &Path,
    security: &dyn Security,
    r: &mut dyn Runtime,
) -> Outcome {
    let verify_identity =
        || -> Result<()> { same_identity(b, &baseline(&t.provision, &t.config, &t.machine)?) };
    if let Err(error) = p.verify(&p.stage).and_then(|_| verify_identity()) {
        return Outcome::new("refused", Some(error));
    }
    if p.verify(&t.install).is_ok() {
        return match r.start().and_then(|_| r.read_receipt()).and_then(|raw| {
            verify_identity()?;
            receipt(b, &raw)
        }) {
            Ok(online) => Outcome::new(
                if online {
                    "already_current_registered"
                } else {
                    "already_current_offline"
                },
                None,
            ),
            Err(e) => Outcome::new("verification_failed", Some(e)),
        };
    }
    let prepare = r
        .stop()
        .and_then(|_| verify_identity())
        .and_then(|_| Snapshot::capture(&[t.install.clone(), t.config.clone()], backup, security));
    let snapshot = match prepare {
        Ok(s) => s,
        Err(error) => {
            let mut out = Outcome::new("refused", Some(error));
            if let Err(e) = r.restore_original_state() {
                out.status = "service_restore_failed";
                out.rollback_error = Some(e)
            }
            return out;
        }
    };
    let changed = p
        .copy_to(&t.install, security)
        .and_then(|_| p.verify(&t.install))
        .and_then(|_| r.start())
        .and_then(|_| r.read_receipt())
        .and_then(|raw| {
            verify_identity()?;
            receipt(b, &raw)
        });
    match changed {
        Ok(online) => Outcome::new(
            if online {
                "updated_registered"
            } else {
                "updated_offline"
            },
            None,
        ),
        Err(error) => {
            let rollback = r
                .stop()
                .and_then(|_| snapshot.restore(security))
                .and_then(|_| verify_identity())
                .and_then(|_| r.restore_original_state());
            match rollback {
                Ok(()) => Outcome::new("rolled_back", Some(error)),
                Err(e) => Outcome {
                    status: "rollback_failed",
                    error: Some(error),
                    rollback_error: Some(e),
                },
            }
        }
    }
}
