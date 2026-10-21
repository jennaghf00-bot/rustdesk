use crate::maintenance_core::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::{secretbox, sign};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
    dir: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(
            std::env::var_os("RUSTDESK_TEST_ROOT").expect("project test root required"),
        );
        assert!(root.is_absolute());
        fs::create_dir_all(&root).unwrap();
        let dir = root.join(format!(
            "maintenance-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self { root, dir }
    }
    fn identity(&self, id: &str, password: &str, encrypted: bool) -> (PathBuf, PathBuf, String) {
        sodiumoxide::init().unwrap();
        let dir = self.dir.join(id);
        fs::create_dir(&dir).unwrap();
        let provision = dir.join("provision.json");
        fs::write(&provision,serde_json::to_vec(&serde_json::json!({"remoteId":id,"unattendedPassword":password,"settingsPassword":"fixture-settings","hbbsAddress":"example.invalid:21116","hbbrAddress":"example.invalid:21117","serverKey":STANDARD.encode([1u8;32])})).unwrap()).unwrap();
        let (pk, sk) = sign::gen_keypair();
        let h1 = STANDARD.encode(Sha256::digest(format!("{password}fixture-salt")));
        let mut stored = format!("01{h1}");
        if encrypted {
            let mut key = b"fixture-machine".to_vec();
            key.resize(32, 0);
            stored = format!(
                "00{}",
                STANDARD.encode(secretbox::seal(
                    password.as_bytes(),
                    &secretbox::Nonce([0; 24]),
                    &secretbox::Key::from_slice(&key).unwrap()
                ))
            );
        }
        let main=toml::Value::try_from(serde_json::json!({"id":id,"enc_id":"","password":stored,"salt":"fixture-salt","key_pair":[sk.0.to_vec(),pk.0.to_vec()]})).unwrap();
        fs::write(dir.join("RustDesk.toml"), toml::to_string(&main).unwrap()).unwrap();
        fs::write(dir.join("RustDesk_local.toml"),format!("[options]\nprivate-forced-remote-id = '{id}'\nprivate-settings-password = 'fixture-settings'\n")).unwrap();
        fs::write(dir.join("RustDesk2.toml"),format!("[options]\ncustom-rendezvous-server = 'example.invalid:21116'\nrelay-server = 'example.invalid:21117'\nkey = '{}'\n",STANDARD.encode([1u8;32]))).unwrap();
        (provision, dir, STANDARD.encode(Sha256::digest(pk.0)))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self.dir.canonicalize().unwrap();
        assert!(path.starts_with(self.root.canonicalize().unwrap()));
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("maintenance-"));
        fs::remove_dir_all(path).unwrap();
    }
}
struct NoSecurity;
impl Security for NoSecurity {
    fn read(&self, _: &Path) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    fn restore(&self, _: &Path, _: &[u8]) -> Result<()> {
        Ok(())
    }
}
#[test]
fn two_devices_keep_their_own_identity_without_configuration_writes() {
    let f = Fixture::new();
    for (id, password) in [("TEST-A", "fixture-one"), ("TEST-B", "fixture-two")] {
        let (p, d, fp) = f.identity(id, password, false);
        let before = fs::read(d.join("RustDesk.toml")).unwrap();
        let b = baseline(&p, &d, b"fixture-machine").unwrap();
        assert_eq!(b.id, id);
        assert_eq!(b.fingerprint, fp);
        assert_eq!(fs::read(d.join("RustDesk.toml")).unwrap(), before);
        assert!(!d.join("RustDesk.identity-backup").exists());
    }
}
#[test]
fn validates_legacy_encrypted_password_without_global_config() {
    let f = Fixture::new();
    let (p, d, _) = f.identity("TEST-A", "fixture-one", true);
    assert!(baseline(&p, &d, b"fixture-machine").is_ok());
    assert_eq!(
        baseline(&p, &d, b"wrong-machine").err(),
        Some("password_conflict")
    );
}
#[test]
fn conflicting_id_is_rejected_without_changing_files() {
    let f = Fixture::new();
    let (p, d, _) = f.identity("TEST-A", "fixture-one", false);
    fs::write(
        d.join("RustDesk_local.toml"),
        "[options]\nprivate-forced-remote-id='OTHER'\n",
    )
    .unwrap();
    assert_eq!(
        baseline(&p, &d, b"fixture-machine").err(),
        Some("identity_conflict")
    );
}
#[test]
fn password_changed_after_provision_is_not_overwritten() {
    let f = Fixture::new();
    let (p, d, _) = f.identity("TEST-A", "fixture-one", false);
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    v["unattendedPassword"] = "different-password".into();
    fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(
        baseline(&p, &d, b"fixture-machine").err(),
        Some("password_conflict")
    );
}
#[test]
fn receipt_distinguishes_offline_from_changed_identity() {
    let f = Fixture::new();
    let (p, d, fp) = f.identity("TEST-A", "fixture-one", false);
    let b = baseline(&p, &d, b"fixture-machine").unwrap();
    let mut r = serde_json::json!({"version":1,"actualId":"TEST-A","publicFingerprint":fp,"persisted":true,"registered":false,"generation":"fixture","errorCode":null});
    assert_eq!(receipt(&b, &r.to_string()), Ok(false));
    r["registered"] = true.into();
    assert_eq!(receipt(&b, &r.to_string()), Ok(true));
    r["actualId"] = "OTHER".into();
    assert_eq!(receipt(&b, &r.to_string()), Err("receipt_identity_changed"));
}
#[test]
fn rejects_unsafe_archive_paths() {
    assert_eq!(
        relative("./rustdesk.exe").unwrap(),
        PathBuf::from("rustdesk.exe")
    );
    for p in [
        "../other",
        "C:\\Windows\\a",
        "/a",
        "a:stream",
        "a/../b",
        "a\\..\\b",
        "a//b",
    ] {
        assert!(relative(p).is_err(), "{p}");
    }
}
#[test]
fn snapshot_restores_files_and_removes_only_changes_inside_its_roots() {
    let f = Fixture::new();
    let root = f.dir.join("installed");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("librustdesk.dll"), b"old").unwrap();
    let backup = f.dir.join("backup");
    fs::create_dir(&backup).unwrap();
    let snap = Snapshot::capture(&[root.clone()], &backup, &NoSecurity).unwrap();
    fs::write(root.join("librustdesk.dll"), b"new").unwrap();
    fs::write(root.join("new-file"), b"new").unwrap();
    fs::write(f.dir.join("unrelated"), b"keep").unwrap();
    snap.restore(&NoSecurity).unwrap();
    assert_eq!(fs::read(root.join("librustdesk.dll")).unwrap(), b"old");
    assert!(!root.join("new-file").exists());
    assert_eq!(fs::read(f.dir.join("unrelated")).unwrap(), b"keep");
}
#[cfg(windows)]
#[test]
fn locked_backup_source_aborts_and_does_not_change_original() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new();
    let root = f.dir.join("installed");
    fs::create_dir(&root).unwrap();
    let path = root.join("librustdesk.dll");
    fs::write(&path, b"old").unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    let backup = f.dir.join("backup");
    fs::create_dir(&backup).unwrap();
    assert!(Snapshot::capture(&[root], &backup, &NoSecurity).is_err());
    drop(lock);
    assert_eq!(fs::read(path).unwrap(), b"old");
}

struct FakeRuntime {
    running: bool,
    fail_start: bool,
    raw: String,
    stops: usize,
    fail_rollback_stop: bool,
    fail_restore: bool,
}
impl Runtime for FakeRuntime {
    fn stop(&mut self) -> Result<()> {
        if self.fail_rollback_stop && self.stops > 0 {
            return Err("service_stop_failed");
        }
        self.running = false;
        self.stops += 1;
        Ok(())
    }
    fn start(&mut self) -> Result<()> {
        if self.fail_start {
            Err("service_start_failed")
        } else {
            self.running = true;
            Ok(())
        }
    }
    fn restore_original_state(&mut self) -> Result<()> {
        if self.fail_restore {
            return Err("service_restore_failed");
        }
        self.running = true;
        Ok(())
    }
    fn read_receipt(&mut self) -> Result<String> {
        Ok(self.raw.clone())
    }
}
fn transaction_fixture(f: &Fixture, id: &str) -> (Target, Payload, Baseline, FakeRuntime, PathBuf) {
    let (p, config, fp) = f.identity(id, "fixture-password", false);
    let install = f.dir.join(format!("install-{id}"));
    fs::create_dir(&install).unwrap();
    let stage = f.dir.join(format!("stage-{id}"));
    fs::create_dir(&stage).unwrap();
    let mut files = vec![];
    for name in ["rustdesk.exe", "librustdesk.dll"] {
        fs::write(install.join(name), b"old").unwrap();
        fs::write(stage.join(name), b"new").unwrap();
        files.push((PathBuf::from(name), bytes_hash(b"new")));
    }
    let b = baseline(&p, &config, b"fixture-machine").unwrap();
    let t = Target {
        install,
        config,
        provision: p,
        machine: b"fixture-machine".to_vec(),
        recovery_roots: vec![],
    };
    let r=FakeRuntime{running:true,fail_start:false,raw:serde_json::json!({"version":1,"actualId":id,"publicFingerprint":fp,"persisted":true,"registered":true,"generation":"fixture","errorCode":null}).to_string(),stops:0,fail_rollback_stop:false,fail_restore:false};
    let backup = f.dir.join(format!("backup-{id}"));
    fs::create_dir(&backup).unwrap();
    (t, Payload { stage, files }, b, r, backup)
}
#[test]
fn complete_upgrade_keeps_original_id_password_and_configuration() {
    let f = Fixture::new();
    for id in ["TEST-A", "TEST-B"] {
        let (t, p, b, mut r, backup) = transaction_fixture(&f, id);
        let before = fs::read(t.config.join("RustDesk.toml")).unwrap();
        let out = upgrade(&t, &p, &b, &backup, &NoSecurity, &mut r);
        assert_eq!(out.status, "updated_registered");
        assert!(r.running);
        assert_eq!(fs::read(t.install.join("librustdesk.dll")).unwrap(), b"new");
        assert_eq!(fs::read(t.config.join("RustDesk.toml")).unwrap(), before);
        let second = upgrade(&t, &p, &b, &backup, &NoSecurity, &mut r);
        assert_eq!(second.status, "already_current_registered");
        assert_eq!(r.stops, 1);
    }
}
#[test]
fn startup_failure_rolls_back_all_program_and_identity_files() {
    let f = Fixture::new();
    let (t, p, b, mut r, backup) = transaction_fixture(&f, "TEST-A");
    r.fail_start = true;
    let out = upgrade(&t, &p, &b, &backup, &NoSecurity, &mut r);
    assert_eq!(out.status, "rolled_back");
    assert!(r.running);
    assert_eq!(fs::read(t.install.join("rustdesk.exe")).unwrap(), b"old");
    assert!(backup.join("snapshot.json").exists());
}
#[test]
fn changed_receipt_identity_rolls_back_but_ordinary_offline_does_not() {
    let f = Fixture::new();
    let (t, p, b, mut r, backup) = transaction_fixture(&f, "TEST-A");
    let mut value: serde_json::Value = serde_json::from_str(&r.raw).unwrap();
    value["actualId"] = "OTHER".into();
    r.raw = value.to_string();
    assert_eq!(
        upgrade(&t, &p, &b, &backup, &NoSecurity, &mut r).status,
        "rolled_back"
    );
    let (t, p, b, mut r, backup) = transaction_fixture(&f, "TEST-B");
    let mut value: serde_json::Value = serde_json::from_str(&r.raw).unwrap();
    value["registered"] = false.into();
    r.raw = value.to_string();
    assert_eq!(
        upgrade(&t, &p, &b, &backup, &NoSecurity, &mut r).status,
        "updated_offline"
    );
    assert_eq!(fs::read(t.install.join("librustdesk.dll")).unwrap(), b"new");
}
#[test]
fn corrupt_staging_never_stops_the_service_or_replaces_files() {
    let f = Fixture::new();
    let (t, p, b, mut r, backup) = transaction_fixture(&f, "TEST-A");
    fs::write(p.stage.join("rustdesk.exe"), b"corrupt").unwrap();
    assert_eq!(
        upgrade(&t, &p, &b, &backup, &NoSecurity, &mut r).status,
        "refused"
    );
    assert_eq!(r.stops, 0);
    assert_eq!(fs::read(t.install.join("rustdesk.exe")).unwrap(), b"old");
}
#[test]
fn partial_copy_failure_restores_earlier_copied_file() {
    let f = Fixture::new();
    let (t, p, b, mut r, backup) = transaction_fixture(&f, "TEST-A");
    fs::remove_file(t.install.join("librustdesk.dll")).unwrap();
    fs::create_dir(t.install.join("librustdesk.dll")).unwrap();
    assert_eq!(
        upgrade(&t, &p, &b, &backup, &NoSecurity, &mut r).status,
        "rolled_back"
    );
    assert_eq!(fs::read(t.install.join("rustdesk.exe")).unwrap(), b"old");
    assert!(t.install.join("librustdesk.dll").is_dir());
}
#[test]
fn installation_preflight_rejects_missing_multiple_foreign_brand_and_custom_accounts() {
    let f = Fixture::new();
    let install = f.dir.join("RustDesk");
    fs::create_dir(&install).unwrap();
    let record = || ServiceRecord {
        name: "RustDesk".into(),
        exe: install.join("RustDesk.exe"),
        args: vec!["--service".into()],
        account: "LocalSystem".into(),
        start: 2,
    };
    let roots = vec![f.dir.clone()];
    assert!(validate_install(&[record()], &install, &roots).is_ok());
    assert_eq!(
        validate_install(&[], &install, &roots),
        Err("service_ambiguous_or_missing")
    );
    assert_eq!(
        validate_install(&[record(), record()], &install, &roots),
        Err("service_ambiguous_or_missing")
    );
    let mut r = record();
    r.name = "OtherBrand".into();
    assert_eq!(
        validate_install(&[r], &install, &roots),
        Err("unsupported_brand")
    );
    let mut r = record();
    r.account = "DOMAIN\\custom".into();
    assert_eq!(
        validate_install(&[r], &install, &roots),
        Err("unsupported_account")
    );
    assert_eq!(
        validate_install(&[record()], &install, &[f.dir.join("different")]),
        Err("untrusted_installation")
    );
}
#[test]
fn damaged_backup_is_rejected_before_restoring_any_installed_file() {
    let f = Fixture::new();
    let root = f.dir.join("installed");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("a"), b"old").unwrap();
    let backup = f.dir.join("backup");
    fs::create_dir(&backup).unwrap();
    let snap = Snapshot::capture(&[root.clone()], &backup, &NoSecurity).unwrap();
    fs::write(root.join("a"), b"new").unwrap();
    fs::write(backup.join("1"), b"corrupted").unwrap();
    assert_eq!(snap.restore(&NoSecurity), Err("backup_checksum_failed"));
    assert_eq!(fs::read(root.join("a")).unwrap(), b"new");
}
#[cfg(windows)]
#[test]
fn real_windows_acl_is_preserved_during_update_and_backup_restoration() {
    use crate::maintenance_windows::{private_dir, WinSecurity};
    let f = Fixture::new();
    let (t, p, b, mut r, backup) = transaction_fixture(&f, "TEST-A");
    let before = WinSecurity
        .read(&t.install.join("librustdesk.dll"))
        .unwrap();
    let protected = f.dir.join("private");
    private_dir(&protected, false).unwrap();
    assert!(private_dir(&protected, false).is_err());
    private_dir(&protected, true).unwrap();
    let private_acl = WinSecurity.read(&protected).unwrap();
    for (path, _) in &p.files {
        WinSecurity
            .restore(&p.stage.join(path), &private_acl)
            .unwrap();
    }
    assert_eq!(
        upgrade(&t, &p, &b, &backup, &WinSecurity, &mut r).status,
        "updated_registered"
    );
    assert_eq!(
        WinSecurity
            .read(&t.install.join("librustdesk.dll"))
            .unwrap(),
        before
    );
}
#[cfg(windows)]
#[test]
fn reparse_target_is_rejected_before_traversal() {
    use std::os::windows::fs::symlink_dir;
    let f = Fixture::new();
    let outside = f.dir.join("outside");
    fs::create_dir(&outside).unwrap();
    let link = f.dir.join("link");
    symlink_dir(&outside, &link).expect("test requires symlink privilege");
    assert_eq!(safe_path(&link), Err("reparse_path"));
    fs::remove_dir(link).unwrap();
}
struct FailingSecurity;
impl Security for FailingSecurity {
    fn read(&self, _: &Path) -> Result<Vec<u8>> {
        Err("acl_read_failed")
    }
    fn restore(&self, _: &Path, _: &[u8]) -> Result<()> {
        Err("acl_restore_failed")
    }
}
#[test]
fn backup_failure_restores_service_state_without_replacing_files() {
    let f = Fixture::new();
    let (t, p, b, mut r, backup) = transaction_fixture(&f, "TEST-A");
    assert_eq!(
        upgrade(&t, &p, &b, &backup, &FailingSecurity, &mut r).status,
        "refused"
    );
    assert!(r.running);
    assert_eq!(fs::read(t.install.join("rustdesk.exe")).unwrap(), b"old");
}
#[cfg(windows)]
#[test]
fn locked_rollback_target_reports_failure_and_preserves_backup() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new();
    let root = f.dir.join("installed");
    fs::create_dir(&root).unwrap();
    let path = root.join("a");
    fs::write(&path, b"old").unwrap();
    let backup = f.dir.join("backup");
    fs::create_dir(&backup).unwrap();
    let snap = Snapshot::capture(&[root], &backup, &NoSecurity).unwrap();
    fs::write(&path, b"new").unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    assert!(snap.restore(&NoSecurity).is_err());
    assert!(backup.join("snapshot.json").exists());
    drop(lock);
    assert_eq!(fs::read(path).unwrap(), b"new");
}
#[test]
fn actual_embedded_archive_has_verified_files_and_no_device_configuration() {
    let (_, files) = crate::archive().unwrap();
    assert_eq!(files.len(), 91);
    assert!(files
        .iter()
        .any(|(p, h)| p == Path::new("librustdesk.dll") && h == DLL_HASH));
}
#[cfg(windows)]
#[test]
fn maintenance_lock_rejects_a_concurrent_upgrade_and_releases_cleanly() {
    use crate::maintenance_windows::acquire_lock;
    let f = Fixture::new();
    let path = f.dir.join("maintenance.lock");
    let first = acquire_lock(&path).unwrap();
    assert!(acquire_lock(&path).is_err());
    drop(first);
    assert!(acquire_lock(&path).is_ok());
}
#[test]
fn failed_rollback_stop_never_overwrites_a_still_running_new_client() {
    let f = Fixture::new();
    let (t, p, b, mut r, backup) = transaction_fixture(&f, "TEST-A");
    r.raw = "invalid receipt".into();
    r.fail_rollback_stop = true;
    let out = upgrade(&t, &p, &b, &backup, &NoSecurity, &mut r);
    assert_eq!(out.status, "rollback_failed");
    assert_eq!(out.rollback_error, Some("service_stop_failed"));
    assert_eq!(fs::read(t.install.join("rustdesk.exe")).unwrap(), b"new");
    assert!(backup.join("snapshot.json").exists());
}
#[test]
fn failed_prior_service_restore_is_not_reported_as_successful_rollback() {
    let f = Fixture::new();
    let (t, p, b, mut r, backup) = transaction_fixture(&f, "TEST-A");
    r.fail_start = true;
    r.fail_restore = true;
    let out = upgrade(&t, &p, &b, &backup, &NoSecurity, &mut r);
    assert_eq!(out.status, "rollback_failed");
    assert_eq!(out.rollback_error, Some("service_restore_failed"));
    assert!(!r.running);
    assert_eq!(fs::read(t.install.join("rustdesk.exe")).unwrap(), b"old");
}
#[cfg(windows)]
#[test]
fn service_path_matches_rustdesk_systemprofile_compatibility_redirect() {
    use crate::maintenance_windows::service_config_dir;
    let windows = Path::new("C:\\Windows");
    let expected = windows.join("ServiceProfiles/LocalService/AppData/Roaming/RustDesk/config");
    assert_eq!(
        service_config_dir(windows, "NT AUTHORITY\\LocalService"),
        expected
    );
    assert_eq!(service_config_dir(windows, "LocalSystem"), expected);
}
#[test]
fn rollback_removes_new_identity_in_a_previously_absent_compatibility_directory() {
    let f = Fixture::new();
    let config = f.dir.join("absent-config");
    let backup = f.dir.join("backup");
    fs::create_dir(&backup).unwrap();
    let snap = Snapshot::capture(&[config.clone()], &backup, &NoSecurity).unwrap();
    fs::create_dir(&config).unwrap();
    fs::write(config.join("RustDesk.toml"), b"unwanted-new-identity").unwrap();
    snap.restore(&NoSecurity).unwrap();
    assert!(!config.exists());
}
