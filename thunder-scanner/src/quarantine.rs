// ==============================================================================
// THUNDER SCANNER - Encrypted Quarantine Vault
// Built by: NEXO-TECH
// ==============================================================================

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use chrono::Utc;
use serde::{Deserialize, Serialize};

const QUARANTINE_XOR_KEY: u8 = 0x7E;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuarantineRecord {
    pub id: String,
    pub original_path: String,
    pub quarantined_path: String,
    pub detection_name: String,
    pub sha256: String,
    pub timestamp: String,
}

pub struct QuarantineVault {
    pub vault_dir: PathBuf,
    pub manifest_file: PathBuf,
}

impl QuarantineVault {
    pub fn new(base_dir: &Path) -> Self {
        let vault_dir = base_dir.join("quarantine");
        let manifest_file = vault_dir.join("manifest.json");
        if !vault_dir.exists() {
            let _ = fs::create_dir_all(&vault_dir);
        }
        Self {
            vault_dir,
            manifest_file,
        }
    }

    pub fn load_manifest(&self) -> Vec<QuarantineRecord> {
        if !self.manifest_file.exists() {
            return Vec::new();
        }
        if let Ok(content) = fs::read_to_string(&self.manifest_file) {
            if let Ok(records) = serde_json::from_str::<Vec<QuarantineRecord>>(&content) {
                return records;
            }
        }
        Vec::new()
    }

    pub fn save_manifest(&self, records: &[QuarantineRecord]) {
        if let Ok(json) = serde_json::to_string_pretty(records) {
            let _ = fs::write(&self.manifest_file, json);
        }
    }

    pub fn quarantine_file(&self, source_path: &Path, threat_name: &str, sha256_hash: &str) -> Result<PathBuf, String> {
        let mut source = File::open(source_path).map_err(|e| format!("Failed to open file: {}", e))?;
        let mut buffer = Vec::new();
        source.read_to_end(&mut buffer).map_err(|e| format!("Failed to read file: {}", e))?;

        // Encrypt buffer with XOR mask
        for byte in buffer.iter_mut() {
            *byte ^= QUARANTINE_XOR_KEY;
        }

        let record_id = format!("{}_{}", Utc::now().timestamp(), sha256_hash.chars().take(8).collect::<String>());
        let dest_filename = format!("{}.vault", record_id);
        let dest_path = self.vault_dir.join(&dest_filename);

        let mut dest = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dest_path)
            .map_err(|e| format!("Failed to write to quarantine vault: {}", e))?;

        dest.write_all(&buffer).map_err(|e| format!("Write failed: {}", e))?;

        // Remove original malicious file
        fs::remove_file(source_path).map_err(|e| format!("Failed to delete source infected file: {}", e))?;

        // Update manifest
        let mut records = self.load_manifest();
        records.push(QuarantineRecord {
            id: record_id,
            original_path: source_path.to_string_lossy().to_string(),
            quarantined_path: dest_path.to_string_lossy().to_string(),
            detection_name: threat_name.to_string(),
            sha256: sha256_hash.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        });
        self.save_manifest(&records);

        Ok(dest_path)
    }

    pub fn restore_file(&self, record_id: &str) -> Result<PathBuf, String> {
        let mut records = self.load_manifest();
        let index = records.iter().position(|r| r.id == record_id || r.sha256.starts_with(record_id))
            .ok_or_else(|| format!("Record with ID {} not found in quarantine vault", record_id))?;

        let record = records.remove(index);
        let vault_file = PathBuf::from(&record.quarantined_path);
        if !vault_file.exists() {
            return Err("Quarantined vault file missing on disk".to_string());
        }

        let mut vault_fh = File::open(&vault_file).map_err(|e| format!("Failed to open vault file: {}", e))?;
        let mut buffer = Vec::new();
        vault_fh.read_to_end(&mut buffer).map_err(|e| format!("Failed to read vault file: {}", e))?;

        // Decrypt
        for byte in buffer.iter_mut() {
            *byte ^= QUARANTINE_XOR_KEY;
        }

        let target_path = PathBuf::from(&record.original_path);
        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        fs::write(&target_path, buffer).map_err(|e| format!("Failed to restore original file: {}", e))?;
        let _ = fs::remove_file(&vault_file);

        self.save_manifest(&records);
        Ok(target_path)
    }
}
