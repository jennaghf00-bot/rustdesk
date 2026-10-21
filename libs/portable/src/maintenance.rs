#![windows_subsystem = "windows"]
#[allow(unexpected_cfgs)]
mod bin_reader;
mod maintenance_core;
#[cfg(test)]
mod maintenance_tests;
#[cfg(windows)]
mod maintenance_windows;
use maintenance_core::*;
use std::{io::Read, path::Path};

fn archive() -> Result<(bin_reader::BinaryReader, Vec<(std::path::PathBuf, String)>)> {
    if bytes_hash(include_bytes!("../data.bin")) != ARCHIVE_HASH {
        return Err("archive_checksum_failed");
    }
    let reader = bin_reader::BinaryReader::default();
    if reader.files.len() != 91 || relative(&reader.exe)? != Path::new("rustdesk.exe") {
        return Err("archive_manifest_invalid");
    }
    let mut files = vec![];
    let mut seen = std::collections::HashSet::new();
    for f in &reader.files {
        let path = relative(&f.path)?;
        if !seen.insert(path.to_string_lossy().to_ascii_lowercase()) {
            return Err("archive_duplicate_path");
        }
        let name = path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_ascii_lowercase();
        if name.contains("provision")
            || name == "id_ed25519"
            || name.starts_with("rustdesk") && name.ends_with(".toml")
        {
            return Err("archive_contains_configuration");
        }
        let mut raw = vec![];
        brotli::Decompressor::new(f.raw, 4096)
            .take(256 * 1024 * 1024)
            .read_to_end(&mut raw)
            .map_err(|_| "archive_decompression_failed")?;
        if format!("{:x}", md5::compute(&raw)) != String::from_utf8_lossy(f.md5_code) {
            return Err("archive_file_checksum_failed");
        }
        let hash = bytes_hash(&raw);
        if name == "librustdesk.dll" && hash != DLL_HASH {
            return Err("archive_native_build_invalid");
        }
        files.push((path, hash));
    }
    Ok((reader, files))
}
fn inspect() -> Result<()> {
    let (_, files) = archive()?;
    println!(
        "{}",
        serde_json::json!({"release":"universal-maintenance-20261021","archiveSha256":ARCHIVE_HASH,"dllSha256":DLL_HASH,"files":files.iter().map(|(p,h)|serde_json::json!({"path":p,"sha256":h})).collect::<Vec<_>>() })
    );
    Ok(())
}
#[cfg(windows)]
fn run() -> Result<()> {
    use maintenance_windows::*;
    if !is_admin() {
        if std::env::args().any(|s| s == "--maintenance-elevated") {
            return Err("administrator_required");
        }
        return elevate();
    }
    sodiumoxide::init().map_err(|_| "crypto_unavailable")?;
    let workspace = Workspace::create()?;
    let result = (|| -> Result<serde_json::Value> {
        let mut host = Host::preflight()?;
        let t = Target {
            install: host.target.install.clone(),
            config: host.target.config.clone(),
            provision: host.target.provision.clone(),
            machine: host.target.machine.clone(),
            recovery_roots: host.target.recovery_roots.clone(),
        };
        let b = baseline(&t.provision, &t.config, &t.machine)?;
        let prompt=format!("Upgrade this existing private RustDesk client?\n\nID: {}\nPath: {}\n\nRemote sessions and RustDesk windows may close briefly. The existing ID, passwords and service account will be preserved.\n\nDo not continue during active production work.",b.id,t.install.display());
        if !dialog(&prompt, true) {
            return Ok(serde_json::json!({"status":"cancelled"}));
        }
        let (reader, files) = archive()?;
        let stage = workspace.run.join("payload");
        private_dir(&stage, false)?;
        for f in &reader.files {
            f.write_to_file(&stage)
                .map_err(|_| "staging_write_failed")?;
        }
        let backup = workspace.run.join("backup");
        private_dir(&backup, false)?;
        let payload = Payload { stage, files };
        let outcome = upgrade(&t, &payload, &b, &backup, &WinSecurity, &mut host);
        Ok(
            serde_json::json!({"version":1,"release":"universal-maintenance-20261021","status":outcome.status,"errorCode":outcome.error,"rollbackError":outcome.rollback_error,"originalId":b.id,"publicFingerprint":b.fingerprint,"backupDir":backup,"dllSha256":DLL_HASH}),
        )
    })();
    let value = match result {
        Ok(v) => v,
        Err(e) => serde_json::json!({"version":1,"status":"refused","errorCode":e}),
    };
    let report = workspace.run.join("report.json");
    std::fs::write(
        &report,
        serde_json::to_vec_pretty(&value).map_err(|_| "report_failed")?,
    )
    .map_err(|_| "report_failed")?;
    println!("{}", value);
    let status = value["status"].as_str().unwrap_or("failed");
    let summary=match status {
        "updated_registered"|"already_current_registered"=>"Client verified. The original ID is registered. Test a remote connection using the original password.",
        "updated_offline"|"already_current_offline"=>"Client files and original identity are verified, but registration is currently offline. This is not a successful remote-connection test.",
        "rolled_back"=>"Upgrade failed. Original files, identity and service state were restored.",
        "rollback_failed"|"service_restore_failed"=>"Upgrade recovery failed. Do not reinstall or rebind. Keep the backup and send the report to your administrator.",
        "cancelled"=>"Cancelled. Installed files were not changed.",
        _=>"Upgrade was refused or verification failed. Do not clear the identity or use another device's installer. Send the report to your administrator.",
    };
    dialog(
        &format!(
            "{}\n\nStatus: {}\nCode: {}\nReport: {}",
            summary,
            status,
            value["errorCode"].as_str().unwrap_or("none"),
            report.display()
        ),
        false,
    );
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = if args == ["--inspect-payload"] {
        inspect()
    } else if args.is_empty() || args == ["--maintenance-elevated"] {
        #[cfg(windows)]
        {
            run()
        }
        #[cfg(not(windows))]
        {
            Err("windows_required")
        }
    } else {
        Err("unsupported_arguments")
    };
    if let Err(e) = result {
        println!("{}", serde_json::json!({"status":"refused","errorCode":e}));
        #[cfg(windows)]
        maintenance_windows::dialog(&format!("No upgrade was completed.\n\nCode: {}", e), false);
        std::process::exit(1);
    }
}
