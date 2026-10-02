// ==============================================================================
// THUNDER SCANNER - Native Rust Antivirus & Malware Cleaning Suite (10-Star)
// Built by: NEXO-TECH
// ==============================================================================

mod signatures;
mod heuristics;
mod quarantine;
mod cleaner;
mod engine;

use std::env;
use std::path::{Path, PathBuf};
use colored::*;
use clap::{Parser, Subcommand};

use crate::engine::ScanEngine;
use crate::quarantine::QuarantineVault;

#[derive(Parser)]
#[command(name = "THUNDER Scanner")]
#[command(author = "NEXO-TECH")]
#[command(version = "2.0.0")]
#[command(about = "Enterprise Antivirus & Threat Remediation Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Target path to scan
    #[arg(short, long)]
    path: Option<String>,

    /// Automatically quarantine detected threats
    #[arg(short, long)]
    quarantine: bool,

    /// Securely shred and permanently destroy detected threats
    #[arg(short, long)]
    shred: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory or file for threats
    Scan {
        /// Target file or directory path
        #[arg(short, long, default_value = ".")]
        path: String,

        /// Automatically move threats to the encrypted quarantine vault
        #[arg(short, long)]
        quarantine: bool,

        /// Permanently shred detected threats
        #[arg(short, long)]
        shred: bool,
    },
    /// Manage the encrypted quarantine vault
    Quarantine {
        /// List all quarantined files
        #[arg(short, long)]
        list: bool,

        /// Restore a quarantined file by Record ID or Hash
        #[arg(short, long)]
        restore: Option<String>,
    },
}

fn print_banner() {
    println!("{}", "================================================================".cyan());
    println!("{}", "          ⚡ THUNDER VIRUS & MALWARE SCANNER ⚡          ".bright_yellow().bold());
    println!("{}", "                     Built by NEXO-TECH                         ".bright_cyan());
    println!("{}", "================================================================".cyan());
}

fn get_central_vault_path() -> PathBuf {
    if let Ok(exe_path) = env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            return parent.to_path_buf();
        }
    }
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn main() {
    print_banner();

    let cli = Cli::parse();
    let root_anchor = get_central_vault_path();
    let vault = QuarantineVault::new(&root_anchor);

    let mut threat_found = false;

    match &cli.command {
        Some(Commands::Scan { path, quarantine, shred }) => {
            threat_found = execute_scan(path, *quarantine, *shred, &vault);
        }
        Some(Commands::Quarantine { list, restore }) => {
            if *list {
                list_quarantine(&vault);
            } else if let Some(rec_id) = restore {
                restore_quarantine(&vault, rec_id);
            } else {
                list_quarantine(&vault);
            }
        }
        None => {
            let target_path = cli.path.unwrap_or_else(|| ".".to_string());
            threat_found = execute_scan(&target_path, cli.quarantine, cli.shred, &vault);
        }
    }

    if threat_found {
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}

fn execute_scan(target_path: &str, quarantine: bool, shred: bool, vault: &QuarantineVault) -> bool {
    let scan_path = Path::new(target_path);
    if !scan_path.exists() {
        println!("{} Path '{}' does not exist.", "[-] Error:".red().bold(), target_path);
        return false;
    }

    println!("{} Deep Inspection Scope : {}", "[+]".green(), target_path.bright_white().bold());
    println!("{} Multi-Engine Pipeline : Cryptographic Hashes + YARA Signatures + PE Section Analysis + Entropy", "[+]".green());
    if quarantine {
        println!("{} Remediation Mode      : {} (XOR-encrypted Sandbox Vault)", "[*]".yellow(), "QUARANTINE".bright_yellow().bold());
    } else if shred {
        println!("{} Remediation Mode      : {} (DoD 5220.22-M Multi-Pass Shred)", "[*]".red(), "SECURE SHRED".bright_red().bold());
    } else {
        println!("{} Remediation Mode      : {} (Audit Only)", "[*]".cyan(), "AUDIT".cyan());
    }

    let mut engine = ScanEngine::default();
    engine.quarantine_mode = quarantine;
    engine.shred_mode = shred;

    let report = engine.scan_path(scan_path, Some(vault));

    println!("\n{}", "====================== SCAN RESULTS ======================".cyan());
    println!("Files Inspected : {}", report.files_scanned.to_string().bright_white().bold());
    println!("Time Elapsed    : {} ms", report.elapsed_millis.to_string().bright_white());
    println!("Threat Status   : {}", if report.threats_found.is_empty() {
        "0 (SYSTEM CLEAN)".bright_green().bold()
    } else {
        format!("{} MALICIOUS THREATS DETECTED", report.threats_found.len()).bright_red().bold()
    });

    if !report.threats_found.is_empty() {
        println!("\n{}", "--- DETECTED THREAT DETAILS ---".bright_red().bold());
        for (idx, threat) in report.threats_found.iter().enumerate() {
            println!("{}. Threat Name : {}", idx + 1, threat.threat_name.bright_red().bold());
            println!("   Category    : {}", threat.category.yellow());
            println!("   Severity    : {}", threat.severity.bright_purple().bold());
            println!("   Location    : {}", threat.file_path.display().to_string().white());
            println!("   Engine Match: {} ({})", threat.detection_type.cyan(), threat.details);
            println!("   SHA256      : {}", threat.sha256.dimmed());
            if quarantine {
                println!("   Action Taken: {}", "MOVED TO ENCRYPTED QUARANTINE VAULT".bright_green());
            } else if shred {
                println!("   Action Taken: {}", "PERMANENTLY SHREDDED & UNLINKED".bright_red());
            }
            println!();
        }
        return true;
    }
    false
}

fn list_quarantine(vault: &QuarantineVault) {
    let records = vault.load_manifest();
    println!("\n{}", "================ ENCRYPTED QUARANTINE VAULT ================".yellow());
    if records.is_empty() {
        println!("The quarantine vault is currently empty.");
        return;
    }

    println!("Total Quarantined Threats: {}\n", records.len());
    for (i, r) in records.iter().enumerate() {
        println!("{}. Record ID    : {}", i + 1, r.id.bright_yellow().bold());
        println!("   Threat Name  : {}", r.detection_name.bright_red());
        println!("   Original Path: {}", r.original_path.white());
        println!("   Vault File   : {}", r.quarantined_path.dimmed());
        println!("   Timestamp    : {}", r.timestamp.cyan());
        println!();
    }
}

fn restore_quarantine(vault: &QuarantineVault, record_id: &str) {
    match vault.restore_file(record_id) {
        Ok(restored_path) => {
            println!("{} Successfully decrypted and restored file to: {}", "[+]".green().bold(), restored_path.display());
        }
        Err(e) => {
            println!("{} Failed to restore: {}", "[-]".red().bold(), e);
        }
    }
}
