// ==============================================================================
// THUNDER SCANNER - Scanning Engine & Detection Coordinator
// Built by: NEXO-TECH
// ==============================================================================

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;
use md5::Md5;
use sha2::{Sha256, Digest};
use walkdir::WalkDir;

use crate::heuristics::analyze_heuristics;
use crate::signatures::{KNOWN_HASHES, PATTERN_SIGNATURES};
use crate::quarantine::QuarantineVault;
use crate::cleaner::ThreatCleaner;

#[derive(Debug, Clone)]
pub struct DetectionItem {
    pub file_path: PathBuf,
    pub threat_name: String,
    pub severity: String,
    pub category: String,
    pub sha256: String,
    pub detection_type: String,
    pub details: String,
}

pub struct ScanReport {
    pub files_scanned: usize,
    pub threats_found: Vec<DetectionItem>,
    pub elapsed_millis: u128,
    pub errors: usize,
}

pub struct ScanEngine {
    pub max_file_size_bytes: u64,
    pub quarantine_mode: bool,
    pub shred_mode: bool,
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 100 * 1024 * 1024, // 100 MB max scan per file
            quarantine_mode: false,
            shred_mode: false,
        }
    }
}

impl ScanEngine {
    pub fn scan_path<P: AsRef<Path>>(&self, target_path: P, vault: Option<&QuarantineVault>) -> ScanReport {
        let start = Instant::now();
        let mut files_scanned = 0;
        let mut threats = Vec::new();
        let mut errors = 0;

        let walker = WalkDir::new(target_path).into_iter();

        for entry_res in walker {
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => {
                    errors += 1;
                    continue;
                }
            };

            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // Skip files inside any directory named quarantine
            if path.components().any(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case("quarantine")) {
                continue;
            }

            // Size check
            if let Ok(meta) = entry.metadata() {
                if meta.len() > self.max_file_size_bytes {
                    continue;
                }
            }

            files_scanned += 1;

            if let Some(detection) = self.scan_single_file(path) {
                // Threat found!
                if self.quarantine_mode {
                    if let Some(v) = vault {
                        let _ = v.quarantine_file(path, &detection.threat_name, &detection.sha256);
                    }
                } else if self.shred_mode {
                    let _ = ThreatCleaner::secure_shred(path);
                }

                threats.push(detection);
            }
        }

        ScanReport {
            files_scanned,
            threats_found: threats,
            elapsed_millis: start.elapsed().as_millis(),
            errors,
        }
    }

    pub fn scan_single_file(&self, path: &Path) -> Option<DetectionItem> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return None,
        };

        let mut buffer = Vec::new();
        if file.read_to_end(&mut buffer).is_err() {
            return None;
        }

        // 1. Calculate Hashes
        let mut md5_hasher = Md5::new();
        md5_hasher.update(&buffer);
        let md5_str = hex::encode(md5_hasher.finalize());

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&buffer);
        let sha256_str = hex::encode(sha256_hasher.finalize());

        // 2. Exact Hash Signature Matching
        for sig in KNOWN_HASHES {
            if sig.hash.eq_ignore_ascii_case(&md5_str) || sig.hash.eq_ignore_ascii_case(&sha256_str) {
                return Some(DetectionItem {
                    file_path: path.to_path_buf(),
                    threat_name: sig.name.to_string(),
                    severity: sig.severity.to_string(),
                    category: sig.category.to_string(),
                    sha256: sha256_str,
                    detection_type: "HASH_SIGNATURE".to_string(),
                    details: format!("Matched known blacklist hash: {}", sig.hash),
                });
            }
        }

        // 3. String & Byte Pattern Matching (Case-Insensitive)
        let file_text_lower = String::from_utf8_lossy(&buffer).to_lowercase();
        for pat in PATTERN_SIGNATURES {
            if file_text_lower.contains(&pat.pattern.to_lowercase()) {
                return Some(DetectionItem {
                    file_path: path.to_path_buf(),
                    threat_name: pat.name.to_string(),
                    severity: pat.severity.to_string(),
                    category: pat.category.to_string(),
                    sha256: sha256_str,
                    detection_type: "PATTERN_SIGNATURE".to_string(),
                    details: format!("Matched malicious pattern: '{}'", pat.pattern),
                });
            }
        }

        // 4. Advanced Heuristic Analysis
        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let heur_result = analyze_heuristics(filename, &buffer);
        if heur_result.is_suspicious {
            return Some(DetectionItem {
                file_path: path.to_path_buf(),
                threat_name: "Heuristic:Suspicious/GenericThreat".to_string(),
                severity: "HIGH".to_string(),
                category: "Heuristic Anomaly".to_string(),
                sha256: sha256_str,
                detection_type: "HEURISTIC_ENGINE".to_string(),
                details: heur_result.reasons.join(" | "),
            });
        }

        None
    }
}
