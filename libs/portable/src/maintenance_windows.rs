use crate::maintenance_core::*;
use std::{
    ffi::OsStr,
    fs,
    io::Read,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::{
    shared::{sddl::*, winerror::*},
    um::{
        errhandlingapi::*, fileapi::*, handleapi::*, processthreadsapi::*, securitybaseapi::*,
        shellapi::*, synchapi::*, sysinfoapi::*, tlhelp32::*, winbase::*, winnt::*, winsvc::*,
        winuser::*,
    },
};
use winreg::{enums::*, RegKey};
// WinBase.h constant omitted by winapi 0.3.
const SCS_64BIT_BINARY: u32 = 6;

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
fn from_wide(s: &[u16]) -> String {
    String::from_utf16_lossy(&s[..s.iter().position(|c| *c == 0).unwrap_or(s.len())])
}
pub fn dialog(text: &str, confirm: bool) -> bool {
    unsafe {
        MessageBoxW(
            null_mut(),
            wide(text).as_ptr(),
            wide("RustDesk Private Update").as_ptr(),
            if confirm {
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2
            } else {
                MB_OK | MB_ICONINFORMATION
            },
        ) == IDYES
    }
}
pub fn is_admin() -> bool {
    let mut sid = [0u8; 68];
    let mut size = sid.len() as u32;
    let mut member = 0;
    unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            sid.as_mut_ptr() as _,
            &mut size,
        ) != 0
            && CheckTokenMembership(null_mut(), sid.as_mut_ptr() as _, &mut member) != 0
            && member != 0
    }
}
pub fn elevate() -> Result<()> {
    let exe = std::env::current_exe().map_err(|_| "executable_unavailable")?;
    let result = unsafe {
        ShellExecuteW(
            null_mut(),
            wide("runas").as_ptr(),
            wide(&exe).as_ptr(),
            wide("--maintenance-elevated").as_ptr(),
            null(),
            SW_SHOWNORMAL,
        )
    };
    if result as usize <= 32 {
        Err("elevation_cancelled")
    } else {
        Ok(())
    }
}
fn privileges() -> Result<()> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err("privilege_unavailable");
        }
        let result = (|| {
            for name in [
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeDebugPrivilege",
            ] {
                let mut luid = std::mem::zeroed();
                if LookupPrivilegeValueW(null(), wide(name).as_ptr(), &mut luid) == 0 {
                    return Err("privilege_unavailable");
                }
                let mut p: TOKEN_PRIVILEGES = std::mem::zeroed();
                p.PrivilegeCount = 1;
                p.Privileges[0] = LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                };
                SetLastError(0);
                if AdjustTokenPrivileges(token, 0, &mut p, 0, null_mut(), null_mut()) == 0
                    || GetLastError() == ERROR_NOT_ALL_ASSIGNED
                {
                    return Err("privilege_unavailable");
                }
            }
            Ok(())
        })();
        CloseHandle(token);
        result
    }
}
pub struct WinSecurity;
impl Security for WinSecurity {
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        safe_path(path)?;
        let mut size = 0;
        let flags =
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        unsafe {
            GetFileSecurityW(wide(path).as_ptr(), flags, null_mut(), 0, &mut size);
        }
        if size == 0 {
            return Err("acl_read_failed");
        }
        let mut data = vec![0u8; size as usize];
        if unsafe {
            GetFileSecurityW(
                wide(path).as_ptr(),
                flags,
                data.as_mut_ptr() as _,
                size,
                &mut size,
            )
        } == 0
        {
            return Err("acl_read_failed");
        }
        Ok(data)
    }
    fn restore(&self, path: &Path, value: &[u8]) -> Result<()> {
        safe_path(path)?;
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(value.as_ptr() as _, &mut control, &mut revision) }
            == 0
        {
            return Err("acl_invalid");
        }
        let flags = OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | if control & SE_DACL_PROTECTED != 0 {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
        if unsafe { SetFileSecurityW(wide(path).as_ptr(), flags, value.as_ptr() as _) } == 0 {
            return Err("acl_restore_failed");
        }
        Ok(())
    }
}
pub fn private_dir(path: &Path, reuse: bool) -> Result<()> {
    safe_path(path)?;
    unsafe {
        let mut descriptor = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").as_ptr(),
            SDDL_REVISION_1 as u32,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            return Err("workspace_acl_failed");
        }
        let mut attributes = std::mem::zeroed::<SECURITY_ATTRIBUTES>();
        attributes.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        attributes.lpSecurityDescriptor = descriptor;
        let made = CreateDirectoryW(wide(path).as_ptr(), &mut attributes);
        let result = if made != 0 {
            Ok(())
        } else if reuse && GetLastError() == ERROR_ALREADY_EXISTS {
            let result = (|| {
                let data = WinSecurity.read(path)?;
                let mut owner = null_mut();
                let mut defaulted = 0;
                if GetSecurityDescriptorOwner(data.as_ptr() as _, &mut owner, &mut defaulted) == 0
                    || (IsWellKnownSid(owner, WinBuiltinAdministratorsSid) == 0
                        && IsWellKnownSid(owner, WinLocalSystemSid) == 0)
                {
                    return Err("untrusted_workspace_owner");
                }
                if SetFileSecurityW(
                    wide(path).as_ptr(),
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    descriptor,
                ) == 0
                {
                    return Err("workspace_acl_failed");
                }
                Ok(())
            })();
            result
        } else {
            Err("workspace_create_failed")
        };
        LocalFree(descriptor as _);
        result
    }
}
fn hklm(path: &str) -> Result<RegKey> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
        .map_err(|_| "registry_read_failed")
}
fn reg_string(key: &RegKey, name: &str) -> Result<String> {
    key.get_value::<String, _>(name)
        .map_err(|_| "registry_read_failed")
}
fn command_parts(line: &str) -> Result<Vec<String>> {
    unsafe {
        let mut count = 0;
        let p = CommandLineToArgvW(wide(line).as_ptr(), &mut count);
        if p.is_null() {
            return Err("service_command_invalid");
        }
        let result = std::slice::from_raw_parts(p, count as usize)
            .iter()
            .map(|item| {
                let mut n = 0;
                while *item.add(n) != 0 {
                    n += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(*item, n))
            })
            .collect();
        LocalFree(p as _);
        Ok(result)
    }
}
fn candidates() -> Result<Vec<ServiceRecord>> {
    let services = hklm("SYSTEM\\CurrentControlSet\\Services")?;
    let mut records = vec![];
    for name in services.enum_keys() {
        let name = name.map_err(|_| "service_enumeration_failed")?;
        let key = services
            .open_subkey(&name)
            .map_err(|_| "service_enumeration_failed")?;
        let line = key.get_value::<String, _>("ImagePath").unwrap_or_default();
        let lower = line.to_ascii_lowercase();
        if !name.eq_ignore_ascii_case("rustdesk")
            && !(lower.contains("rustdesk") && lower.contains("--service"))
            && !name.contains("\u{4f17}\u{535a}\u{4fe1}")
        {
            continue;
        }
        let mut parts = command_parts(&line)?;
        if parts.is_empty() {
            return Err("service_command_invalid");
        }
        records.push(ServiceRecord {
            name,
            exe: PathBuf::from(parts.remove(0)),
            args: parts,
            account: reg_string(&key, "ObjectName")?,
            start: key.get_value("Start").map_err(|_| "registry_read_failed")?,
        });
    }
    Ok(records)
}
fn windows_dir() -> Result<PathBuf> {
    let mut path = [0u16; 32768];
    let n = unsafe { GetWindowsDirectoryW(path.as_mut_ptr(), path.len() as u32) };
    if n == 0 || n as usize >= path.len() {
        return Err("windows_path_unavailable");
    }
    Ok(PathBuf::from(from_wide(&path[..n as usize])))
}
fn process_paths() -> Result<Vec<(u32, PathBuf)>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err("process_enumeration_failed");
        }
        let result = (|| {
            let mut entry = std::mem::zeroed::<PROCESSENTRY32W>();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut more = Process32FirstW(snapshot, &mut entry);
            let mut paths = vec![];
            while more != 0 {
                let name = from_wide(&entry.szExeFile);
                if name.eq_ignore_ascii_case("rustdesk.exe")
                    || name.eq_ignore_ascii_case("RuntimeBroker_rustdesk.exe")
                {
                    let process =
                        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
                    if process.is_null() {
                        return Err("process_path_unavailable");
                    }
                    let mut text = vec![0u16; 32768];
                    let mut size = text.len() as u32;
                    let ok = QueryFullProcessImageNameW(process, 0, text.as_mut_ptr(), &mut size);
                    CloseHandle(process);
                    if ok == 0 {
                        return Err("process_path_unavailable");
                    }
                    paths.push((
                        entry.th32ProcessID,
                        PathBuf::from(from_wide(&text[..size as usize])),
                    ));
                }
                more = Process32NextW(snapshot, &mut entry);
            }
            Ok(paths)
        })();
        CloseHandle(snapshot);
        result
    }
}
fn belongs(path: &Path, install: &Path) -> bool {
    path.parent()
        .map(|p| {
            p.to_string_lossy()
                .eq_ignore_ascii_case(&install.to_string_lossy())
        })
        .unwrap_or(false)
}
fn foreign_processes(install: &Path) -> Result<()> {
    if process_paths()?.iter().any(|(_, p)| !belongs(p, install)) {
        Err("foreign_rustdesk_process")
    } else {
        Ok(())
    }
}
struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
fn open_service() -> Result<Service> {
    unsafe {
        let manager = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err("service_access_failed");
        }
        let service = OpenServiceW(
            manager,
            wide("RustDesk").as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
        );
        CloseServiceHandle(manager);
        if service.is_null() {
            Err("service_access_failed")
        } else {
            Ok(Service(service))
        }
    }
}
fn state(service: &Service) -> Result<u32> {
    unsafe {
        let mut s = std::mem::zeroed::<SERVICE_STATUS_PROCESS>();
        let mut bytes = 0;
        if QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            &mut s as *mut _ as _,
            std::mem::size_of_val(&s) as u32,
            &mut bytes,
        ) == 0
        {
            Err("service_status_failed")
        } else {
            Ok(s.dwCurrentState)
        }
    }
}
fn wait_state(service: &Service, desired: u32) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if state(service)? == desired {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("service_transition_timeout");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
pub struct Host {
    pub target: Target,
    original_running: bool,
    record_signature: String,
}
fn signature(records: &[ServiceRecord]) -> String {
    records
        .iter()
        .map(|r| {
            format!(
                "{}|{}|{}|{}|{:?}",
                r.name,
                r.exe.display(),
                r.account,
                r.start,
                r.args
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}
pub fn service_config_dir(windows: &Path, _account: &str) -> PathBuf {
    // Match hbb_common::config::patch, including its LocalSystem compatibility redirect.
    windows.join("ServiceProfiles/LocalService/AppData/Roaming/RustDesk/config")
}
impl Host {
    pub fn preflight() -> Result<Self> {
        privileges()?;
        let records = candidates()?;
        let key = hklm("SOFTWARE\\Microsoft\\Windows\\CurrentVersion")?;
        let roots = vec![PathBuf::from(reg_string(&key, "ProgramFilesDir")?)];
        let uninstall = hklm("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\RustDesk")?;
        let install =
            PathBuf::from(reg_string(&uninstall, "InstallLocation")?.trim_end_matches('\\'));
        validate_install(&records, &install, &roots)?;
        let mut binary_type = 0;
        if unsafe { GetBinaryTypeW(wide(&records[0].exe).as_ptr(), &mut binary_type) } == 0
            || binary_type != SCS_64BIT_BINARY
        {
            return Err("unsupported_executable_architecture");
        }
        let wow = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\RustDesk",
            KEY_READ | KEY_WOW64_32KEY,
        );
        if wow.is_ok() {
            return Err("multiple_install_records");
        }
        foreign_processes(&install)?;
        let config = service_config_dir(&windows_dir()?, &records[0].account);
        safe_path(&config)?;
        let machine = reg_string(&hklm("SOFTWARE\\Microsoft\\Cryptography")?, "MachineGuid")?
            .trim()
            .as_bytes()
            .to_vec();
        if machine.is_empty() {
            return Err("machine_identity_unavailable");
        }
        let service = open_service()?;
        let status = state(&service)?;
        if status != SERVICE_RUNNING && status != SERVICE_STOPPED {
            return Err("service_busy");
        }
        let provision = install.join("rustdesk-private-provision.json");
        let before = baseline(&provision, &config, &machine)?;
        let installed_hash = file_hash(&install.join("librustdesk.dll"))?;
        if status == SERVICE_RUNNING
            && [
                DLL_HASH,
                "1c99f53048c21bc04c2e54faf65d320f02ca51e9401deb0c33d1e4800bbb1efe",
            ]
            .contains(&installed_hash.as_str())
        {
            // Only these known builds support this read-only flag. Never execute unknown legacy builds.
            receipt(&before, &query_receipt(&install.join("rustdesk.exe"))?)?;
        }
        Ok(Self {
            target: Target {
                install,
                config,
                provision,
                machine,
            },
            original_running: status == SERVICE_RUNNING,
            record_signature: signature(&records),
        })
    }
    fn unchanged_registration(&self) -> Result<()> {
        if signature(&candidates()?) != self.record_signature {
            Err("service_registration_changed")
        } else {
            Ok(())
        }
    }
}
fn query_receipt(exe: &Path) -> Result<String> {
    let mut child = Command::new(exe)
        .arg("--private-binding-receipt")
        .env_remove("RUSTDESK_PRIVATE_INLINE_ACTIVATION")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "receipt_spawn_failed")?;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err("receipt_process_failed");
                }
                let mut raw = String::new();
                child
                    .stdout
                    .take()
                    .ok_or("receipt_unavailable")?
                    .take(16384)
                    .read_to_string(&mut raw)
                    .map_err(|_| "receipt_unavailable")?;
                return Ok(raw);
            }
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("receipt_unavailable");
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("receipt_timeout");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
impl Runtime for Host {
    fn stop(&mut self) -> Result<()> {
        self.unchanged_registration()?;
        foreign_processes(&self.target.install)?;
        let service = open_service()?;
        let status = state(&service)?;
        if status != SERVICE_STOPPED {
            if status != SERVICE_STOP_PENDING {
                let mut s = unsafe { std::mem::zeroed() };
                if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut s) } == 0
                    && unsafe { GetLastError() } != ERROR_SERVICE_NOT_ACTIVE
                {
                    return Err("service_stop_failed");
                }
            }
            wait_state(&service, SERVICE_STOPPED)?;
        }
        for _ in 0..3 {
            let processes = process_paths()?;
            if processes.is_empty() {
                return Ok(());
            }
            for (pid, path) in processes {
                if !belongs(&path, &self.target.install) {
                    return Err("foreign_rustdesk_process");
                }
                unsafe {
                    let p = OpenProcess(
                        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                        0,
                        pid,
                    );
                    if p.is_null() {
                        return Err("process_stop_failed");
                    }
                    let mut text = vec![0u16; 32768];
                    let mut len = text.len() as u32;
                    let ok = QueryFullProcessImageNameW(p, 0, text.as_mut_ptr(), &mut len) != 0
                        && PathBuf::from(from_wide(&text[..len as usize])) == path;
                    if !ok || TerminateProcess(p, 0) == 0 {
                        CloseHandle(p);
                        return Err("process_stop_failed");
                    }
                    let waited = WaitForSingleObject(p, 10000);
                    CloseHandle(p);
                    if waited != WAIT_OBJECT_0 {
                        return Err("process_stop_timeout");
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        Err("process_restart_detected")
    }
    fn start(&mut self) -> Result<()> {
        self.unchanged_registration()?;
        let service = open_service()?;
        if state(&service)? != SERVICE_RUNNING
            && unsafe { StartServiceW(service.0, 0, null_mut()) } == 0
            && unsafe { GetLastError() } != ERROR_SERVICE_ALREADY_RUNNING
        {
            return Err("service_start_failed");
        }
        wait_state(&service, SERVICE_RUNNING)
    }
    fn restore_original_state(&mut self) -> Result<()> {
        if self.original_running {
            self.start()
        } else {
            self.stop()
        }
    }
    fn read_receipt(&mut self) -> Result<String> {
        self.unchanged_registration()?;
        if file_hash(&self.target.install.join("librustdesk.dll"))? != DLL_HASH {
            return Err("receipt_build_not_verified");
        }
        let before = baseline(
            &self.target.provision,
            &self.target.config,
            &self.target.machine,
        )?;
        let deadline = Instant::now() + Duration::from_secs(65);
        let mut offline = None;
        while Instant::now() < deadline {
            if state(&open_service()?)? != SERVICE_RUNNING {
                return Err("service_not_running");
            }
            if let Ok(raw) = query_receipt(&self.target.install.join("rustdesk.exe")) {
                match receipt(&before, &raw) {
                    Ok(true) => return Ok(raw),
                    Ok(false) => offline = Some(raw),
                    Err("receipt_identity_changed") | Err("registration_rejected") => {
                        return Err("service_identity_rejected")
                    }
                    Err(_) => {}
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        offline.ok_or("receipt_unavailable")
    }
}
pub struct Workspace {
    pub run: PathBuf,
    _lock: fs::File,
}
pub fn acquire_lock(path: &Path) -> Result<fs::File> {
    safe_path(path)?;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
        .map_err(|_| "maintenance_already_running")
}
impl Workspace {
    pub fn create() -> Result<Self> {
        let root = PathBuf::from(reg_string(
            &hklm("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders")?,
            "Common AppData",
        )?)
        .join("RustDeskPrivateMaintenance");
        private_dir(&root, true)?;
        let lock = acquire_lock(&root.join("maintenance.lock"))?;
        let run = root.join(bytes_hash(&sodiumoxide::randombytes::randombytes(16)));
        private_dir(&run, false)?;
        Ok(Self { run, _lock: lock })
    }
}
