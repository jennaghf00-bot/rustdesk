#![windows_subsystem = "windows"]

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use bin_reader::BinaryReader;

pub mod bin_reader;
#[cfg(windows)]
mod ui;

#[cfg(all(windows, not(test)))]
const APP_METADATA: &[u8] = include_bytes!("../app_metadata.toml");
#[cfg(any(not(windows), test))]
const APP_METADATA: &[u8] = &[];
const APP_METADATA_CONFIG: &str = "meta.toml";
const META_LINE_PREFIX_TIMESTAMP: &str = "timestamp = ";
const APP_PREFIX: &str = "rustdesk";
const APPNAME_RUNTIME_ENV_KEY: &str = "RUSTDESK_APPNAME";
const PRIVATE_INLINE_ACTIVATION_ENV_KEY: &str = "RUSTDESK_PRIVATE_INLINE_ACTIVATION";
const PRIVATE_INLINE_ACTIVATION_MARKER: &[u8] = b"\nRUSTDESK_PRIVATE_INLINE_ACTIVATION_V1:";
#[cfg(windows)]
const SET_FOREGROUND_WINDOW_ENV_KEY: &str = "SET_FOREGROUND_WINDOW";

fn is_timestamp_matches(dir: &Path, ts: &mut u64) -> bool {
    let Ok(app_metadata) = std::str::from_utf8(APP_METADATA) else {
        return true;
    };
    for line in app_metadata.lines() {
        if line.starts_with(META_LINE_PREFIX_TIMESTAMP) {
            if let Ok(stored_ts) = line.replace(META_LINE_PREFIX_TIMESTAMP, "").parse::<u64>() {
                *ts = stored_ts;
                break;
            }
        }
    }
    if *ts == 0 {
        return true;
    }

    if let Ok(content) = std::fs::read_to_string(dir.join(APP_METADATA_CONFIG)) {
        for line in content.lines() {
            if line.starts_with(META_LINE_PREFIX_TIMESTAMP) {
                if let Ok(stored_ts) = line.replace(META_LINE_PREFIX_TIMESTAMP, "").parse::<u64>() {
                    return *ts == stored_ts;
                }
            }
        }
    }
    false
}

fn write_meta(dir: &Path, ts: u64) {
    let meta_file = dir.join(APP_METADATA_CONFIG);
    if ts != 0 {
        let content = format!("{}{}", META_LINE_PREFIX_TIMESTAMP, ts);
        // Ignore is ok here
        let _ = std::fs::write(meta_file, content);
    }
}

fn private_install_dir(shared_cache: &Path) -> std::io::Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = shared_cache.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private extraction parent missing",
        )
    })?;
    let root = parent.join("rustdesk-private-installs");
    std::fs::create_dir_all(&root)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?
        .as_nanos();
    let dir = root.join(format!(
        "{}-{now}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

fn setup(
    reader: BinaryReader,
    dir: Option<PathBuf>,
    clear: bool,
    _args: &Vec<String>,
    _ui: &mut bool,
    private_inline_activation: Option<&str>,
) -> Option<PathBuf> {
    let dir = if let Some(dir) = dir {
        dir
    } else {
        // home dir
        if let Some(dir) = dirs::data_local_dir() {
            dir.join(APP_PREFIX)
        } else {
            eprintln!("not found data local dir");
            return None;
        }
    };

    // A private installer must never reuse another process's DLLs or device footer.
    let private_install = private_inline_activation.is_some();
    let dir = if private_install {
        match private_install_dir(&dir) {
            Ok(dir) => dir,
            Err(error) => {
                eprintln!("private extraction directory failed: {error}");
                return None;
            }
        }
    } else {
        dir
    };

    let mut ts = 0;
    if clear || !is_timestamp_matches(&dir, &mut ts) {
        #[cfg(windows)]
        if _args.is_empty() {
            *_ui = true;
            ui::setup();
        }
        if !private_install {
            std::fs::remove_dir_all(&dir).ok();
        }
    }
    for file in reader.files.iter() {
        if let Err(error) = file.write_to_file(&dir) {
            eprintln!("extraction failed for {}: {error}", file.path);
            return None;
        }
    }
    write_meta(&dir, ts);
    #[cfg(windows)]
    win::copy_runtime_broker(&dir);
    #[cfg(linux)]
    reader.configure_permission(&dir);
    let executable = dir.join(&reader.exe);
    if let Some(payload) = private_inline_activation {
        if let Err(error) = persist_private_inline_activation(&executable, payload) {
            eprintln!("private activation staging failed: {error}");
            return None;
        }
    }
    Some(executable)
}

fn private_inline_activation_from_current_exe() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let data = std::fs::read(exe).ok()?;
    let marker = find_last_subslice(&data, PRIVATE_INLINE_ACTIVATION_MARKER)?;
    let payload = &data[marker + PRIVATE_INLINE_ACTIVATION_MARKER.len()..];
    let payload = std::str::from_utf8(payload).ok()?.trim();
    if payload.is_empty() {
        None
    } else {
        Some(payload.to_owned())
    }
}

fn persist_private_inline_activation(executable: &Path, payload: &str) -> std::io::Result<()> {
    let mut data = std::fs::read(executable)?;
    if let Some(marker) = find_last_subslice(&data, PRIVATE_INLINE_ACTIVATION_MARKER) {
        data.truncate(marker);
    }
    data.extend_from_slice(PRIVATE_INLINE_ACTIVATION_MARKER);
    data.extend_from_slice(payload.as_bytes());
    std::fs::write(executable, data)
}

fn find_last_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

fn should_click_setup(arg_exe: &str, args: &[String], has_private_inline_activation: bool) -> bool {
    if !args.is_empty() {
        return false;
    }
    let exe_lower = arg_exe.to_lowercase();
    exe_lower.ends_with(".exe")
        && (has_private_inline_activation
            || exe_lower.ends_with("install.exe")
            || exe_lower.contains("-install "))
}

fn use_null_stdio() -> bool {
    #[cfg(windows)]
    {
        // When running in CMD on Windows 7, using Stdio::inherit() with spawn returns an "invalid handle" error.
        // Since using Stdio::null() didn’t cause any issues, and determining whether the program is launched from CMD or by double-clicking would require calling more APIs during startup, we also use Stdio::null() when launched by double-clicking on Windows 7.
        let is_windows_7 = is_windows_7();
        println!("is windows7: {}", is_windows_7);
        return is_windows_7;
    }
    #[cfg(not(windows))]
    false
}

#[cfg(windows)]
fn is_windows_7() -> bool {
    use windows::Wdk::System::SystemServices::RtlGetVersion;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

    unsafe {
        let mut version_info = OSVERSIONINFOW::default();
        version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

        if RtlGetVersion(&mut version_info).is_ok() {
            // Windows 7 is version 6.1
            println!(
                "Windows version: {}.{}",
                version_info.dwMajorVersion, version_info.dwMinorVersion
            );
            return version_info.dwMajorVersion == 6 && version_info.dwMinorVersion == 1;
        }
    }
    false
}

fn execute(path: PathBuf, args: Vec<String>, _ui: bool, private_inline_activation: Option<&str>) {
    println!("executing {}", path.display());
    // setup env
    let exe = std::env::current_exe().unwrap_or_default();
    let exe_name = exe.file_name().unwrap_or_default();
    // run executable
    let mut cmd = Command::new(path);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(winapi::um::winbase::CREATE_NO_WINDOW);
        if _ui {
            cmd.env(SET_FOREGROUND_WINDOW_ENV_KEY, "1");
        }
    }

    cmd.env(APPNAME_RUNTIME_ENV_KEY, exe_name);
    if let Some(payload) = private_inline_activation {
        cmd.env(PRIVATE_INLINE_ACTIVATION_ENV_KEY, payload);
    }
    if use_null_stdio() {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    } else {
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }
    let _child = cmd.spawn();

    #[cfg(windows)]
    if _ui {
        match _child {
            Ok(child) => unsafe {
                winapi::um::winuser::AllowSetForegroundWindow(child.id() as u32);
            },
            Err(e) => {
                eprintln!("{:?}", e);
            }
        }
    }
}

fn main() {
    let mut args = Vec::new();
    let mut arg_exe = Default::default();
    let mut i = 0;
    for arg in std::env::args() {
        if i == 0 {
            arg_exe = arg.clone();
        } else {
            args.push(arg);
        }
        i += 1;
    }
    let private_inline_activation = private_inline_activation_from_current_exe();
    // Browsers often save repeated downloads as "...-install (1).exe".
    // Treat those as installers too so users do not accidentally run portable mode.
    let click_setup = should_click_setup(&arg_exe, &args, private_inline_activation.is_some());
    #[cfg(windows)]
    let quick_support = args.is_empty() && win::is_quick_support_exe(&arg_exe);
    #[cfg(not(windows))]
    let quick_support = false;

    let mut ui = false;
    let reader = BinaryReader::default();
    if let Some(exe) = setup(
        reader,
        None,
        click_setup || args.contains(&"--silent-install".to_owned()),
        &args,
        &mut ui,
        private_inline_activation.as_deref(),
    ) {
        if click_setup {
            args = vec!["--install".to_owned()];
        } else if quick_support {
            args = vec!["--quick_support".to_owned()];
        }
        execute(exe, args, ui, private_inline_activation.as_deref());
    } else if private_inline_activation.is_some() {
        #[cfg(windows)]
        win::show_extraction_error();
    }
}

#[cfg(test)]
mod tests {
    use super::{setup, should_click_setup, BinaryReader};
    use crate::bin_reader::BinaryData;
    use std::{
        fs,
        io::Write,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        dir: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = PathBuf::from(
                std::env::var_os("RUSTDESK_TEST_ROOT")
                    .expect("set RUSTDESK_TEST_ROOT inside the project"),
            );
            assert!(root.is_absolute());
            fs::create_dir_all(&root).unwrap();
            let dir = root.join(format!(
                "portable-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            Self { root, dir }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let dir = self.dir.canonicalize().unwrap();
            let root = self.root.canonicalize().unwrap();
            assert!(
                dir.starts_with(root)
                    && dir
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("portable-")
            );
            fs::remove_dir_all(dir).unwrap();
        }
    }

    fn file(path: &str, contents: &[u8]) -> BinaryData {
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
            writer.write_all(contents).unwrap();
        }
        BinaryData {
            path: path.to_owned(),
            raw: Box::leak(compressed.into_boxed_slice()),
            md5_code: Box::leak(
                format!("{:x}", md5::compute(contents))
                    .into_bytes()
                    .into_boxed_slice(),
            ),
        }
    }

    fn reader() -> BinaryReader {
        BinaryReader {
            files: vec![
                file("rustdesk.exe", b"new-exe"),
                file("librustdesk.dll", b"new-dll"),
            ],
            exe: "rustdesk.exe".into(),
        }
    }

    fn extract(reader: BinaryReader, dir: PathBuf, private: Option<&str>) -> Option<PathBuf> {
        setup(
            reader,
            Some(dir),
            false,
            &vec!["--test".into()],
            &mut false,
            private,
        )
    }

    #[test]
    fn private_installations_do_not_overwrite_each_others_payload_or_shared_cache() {
        let fixture = Fixture::new();
        let shared = fixture.dir.join("rustdesk");
        fs::create_dir(&shared).unwrap();
        fs::write(shared.join("librustdesk.dll"), b"old-dll").unwrap();
        let first = extract(reader(), shared.clone(), Some("first-payload")).unwrap();
        let first_bytes = fs::read(&first).unwrap();
        let second = extract(reader(), shared.clone(), Some("second-payload")).unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read(first).unwrap(), first_bytes);
        assert_eq!(
            fs::read(shared.join("librustdesk.dll")).unwrap(),
            b"old-dll"
        );
        assert!(fs::read(second).unwrap().ends_with(b"second-payload"));
    }

    #[test]
    fn corrupt_archive_file_never_returns_an_executable() {
        let fixture = Fixture::new();
        let mut broken = reader();
        broken.files[1].md5_code = b"00000000000000000000000000000000";
        assert!(extract(
            broken,
            fixture.dir.join("rustdesk"),
            Some("fixture-payload")
        )
        .is_none());
    }

    #[test]
    fn missing_payload_target_never_returns_an_executable() {
        let fixture = Fixture::new();
        let mut broken = reader();
        broken.exe = "missing.exe".into();
        assert!(extract(
            broken,
            fixture.dir.join("rustdesk"),
            Some("fixture-payload")
        )
        .is_none());
    }

    #[cfg(windows)]
    #[test]
    fn private_installation_ignores_a_locked_old_shared_dll() {
        use std::os::windows::fs::OpenOptionsExt;
        let fixture = Fixture::new();
        let shared = fixture.dir.join("rustdesk");
        fs::create_dir(&shared).unwrap();
        let old = shared.join("librustdesk.dll");
        fs::write(&old, b"old-dll").unwrap();
        let lock = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&old)
            .unwrap();
        let exe = extract(reader(), shared.clone(), Some("fixture-payload")).unwrap();
        assert_ne!(exe.parent().unwrap(), shared);
        assert_eq!(
            fs::read(exe.parent().unwrap().join("librustdesk.dll")).unwrap(),
            b"new-dll"
        );
        drop(lock);
        assert_eq!(fs::read(old).unwrap(), b"old-dll");
    }

    #[cfg(windows)]
    #[test]
    fn failed_overwrite_never_returns_a_stale_executable() {
        use std::os::windows::fs::OpenOptionsExt;
        let fixture = Fixture::new();
        fs::write(fixture.dir.join("librustdesk.dll"), b"old-dll").unwrap();
        let lock = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(fixture.dir.join("librustdesk.dll"))
            .unwrap();
        assert!(extract(reader(), fixture.dir.clone(), None).is_none());
        drop(lock);
    }

    #[test]
    fn private_inline_activation_forces_install_mode_when_filename_is_truncated() {
        assert!(should_click_setup(
            "ZBX-0040--zbxcfg-truncated.exe",
            &[],
            true
        ));
    }

    #[test]
    fn repeated_download_install_name_still_installs() {
        assert!(should_click_setup("ZBX-0040-install (1).exe", &[], false));
    }

    #[test]
    fn non_private_plain_exe_without_install_name_stays_portable() {
        assert!(!should_click_setup("rustdesk.exe", &[], false));
    }
}

#[cfg(windows)]
mod win {
    use std::{fs, os::windows::process::CommandExt, path::Path, process::Command};

    // Used for privacy mode(magnifier impl).
    pub const RUNTIME_BROKER_EXE: &'static str = "C:\\Windows\\System32\\RuntimeBroker.exe";
    pub const WIN_TOPMOST_INJECTED_PROCESS_EXE: &'static str = "RuntimeBroker_rustdesk.exe";

    pub(super) fn show_extraction_error() {
        let title: Vec<u16> = "RustDesk installation failed\0".encode_utf16().collect();
        let message: Vec<u16> = "Client files could not be extracted or verified. The installed client was not changed. Run the installer again or contact your administrator.\0".encode_utf16().collect();
        unsafe {
            winapi::um::winuser::MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                winapi::um::winuser::MB_OK | winapi::um::winuser::MB_ICONERROR,
            );
        }
    }

    pub(super) fn copy_runtime_broker(dir: &Path) {
        let src = RUNTIME_BROKER_EXE;
        let tgt = WIN_TOPMOST_INJECTED_PROCESS_EXE;
        let target_file = dir.join(tgt);
        if target_file.exists() {
            if let (Ok(src_file), Ok(tgt_file)) = (fs::read(src), fs::read(&target_file)) {
                let src_md5 = format!("{:x}", md5::compute(&src_file));
                let tgt_md5 = format!("{:x}", md5::compute(&tgt_file));
                if src_md5 == tgt_md5 {
                    return;
                }
            }
        }
        let _allow_err = Command::new("taskkill")
            .args(&["/F", "/IM", "RuntimeBroker_rustdesk.exe"])
            .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
            .output();
        let _allow_err = std::fs::copy(src, &format!("{}\\{}", dir.to_string_lossy(), tgt));
    }

    /// Check if the executable is a Quick Support version.
    /// Note: This function must be kept in sync with `src/core_main.rs`.
    #[inline]
    pub(super) fn is_quick_support_exe(exe: &str) -> bool {
        let exe = exe.to_lowercase();
        exe.contains("-qs-") || exe.contains("-qs.exe") || exe.contains("_qs.exe")
    }
}
