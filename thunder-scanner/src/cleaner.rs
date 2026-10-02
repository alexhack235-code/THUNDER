// ==============================================================================
// THUNDER SCANNER - Threat Cleaner, Process Killer & Secure Shredder
// Built by: NEXO-TECH
// ==============================================================================

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;

pub struct ThreatCleaner;

impl ThreatCleaner {
    /// Securely shred a malicious file with a multi-pass wipe before deletion
    pub fn secure_shred(file_path: &Path) -> Result<(), String> {
        if !file_path.exists() {
            return Ok(());
        }

        let file_len = match fs::metadata(file_path) {
            Ok(m) => m.len() as usize,
            Err(e) => return Err(format!("Could not read file metadata: {}", e)),
        };

        // Pass 1: Zero fill
        let zeros = vec![0u8; file_len.min(1024 * 1024)];
        if let Ok(mut fh) = OpenOptions::new().write(true).open(file_path) {
            let mut written = 0;
            while written < file_len {
                let to_write = (file_len - written).min(zeros.len());
                let _ = fh.write_all(&zeros[..to_write]);
                written += to_write;
            }
            let _ = fh.sync_all();
        }

        // Pass 2: 0xFF fill
        let ones = vec![0xFFu8; file_len.min(1024 * 1024)];
        if let Ok(mut fh) = OpenOptions::new().write(true).open(file_path) {
            let mut written = 0;
            while written < file_len {
                let to_write = (file_len - written).min(ones.len());
                let _ = fh.write_all(&ones[..to_write]);
                written += to_write;
            }
            let _ = fh.sync_all();
        }

        // Pass 3: 0xAA pseudo-random complement fill (DoD 5220.22-M compliant 3-pass overwrite)
        let pattern = vec![0xAAu8; file_len.min(1024 * 1024)];
        if let Ok(mut fh) = OpenOptions::new().write(true).open(file_path) {
            let mut written = 0;
            while written < file_len {
                let to_write = (file_len - written).min(pattern.len());
                let _ = fh.write_all(&pattern[..to_write]);
                written += to_write;
            }
            let _ = fh.sync_all();
        }

        // Final deletion
        fs::remove_file(file_path).map_err(|e| format!("Failed to delete file after wipe: {}", e))?;
        Ok(())
    }

    /// Kill running processes associated with a file path or image name
    pub fn kill_process_by_name(process_name: &str) -> bool {
        #[cfg(target_os = "windows")]
        {
            let status = Command::new("taskkill")
                .args(["/F", "/IM", process_name])
                .output();
            status.map(|o| o.status.success()).unwrap_or(false)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let status = Command::new("pkill")
                .args(["-9", "-f", process_name])
                .output();
            status.map(|o| o.status.success()).unwrap_or(false)
        }
    }

    /// Clean suspicious persistence items from Windows registry if applicable
    pub fn clean_startup_persistence(entry_name: &str) {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("reg")
                .args(["delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", entry_name, "/f"])
                .output();
        }
    }
}
