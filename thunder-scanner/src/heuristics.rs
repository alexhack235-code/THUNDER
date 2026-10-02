// ==============================================================================
// THUNDER SCANNER - Advanced Heuristic Engine & PE Inspector
// Built by: NEXO-TECH
// ==============================================================================

pub struct HeuristicResult {
    pub is_suspicious: bool,
    pub score: u32,
    pub reasons: Vec<String>,
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count > 0 {
            let p = (count as f64) / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn analyze_heuristics(filename: &str, data: &[u8]) -> HeuristicResult {
    let mut score = 0;
    let mut reasons = Vec::new();
    let lower_name = filename.to_lowercase();

    // 1. Check Shannon Entropy (High entropy indicates packed malware/ransomware payload)
    let entropy = calculate_entropy(data);
    if data.len() > 1024 && entropy > 7.35 {
        score += 35;
        reasons.push(format!("High Shannon Entropy ({:.2} / 8.0) - Likely Packed, Obfuscated or Encrypted", entropy));
    }

    // 2. Portable Executable (PE) Analysis for .exe, .dll, .sys
    if data.len() > 64 && data[0] == 0x4D && data[1] == 0x5A { // 'MZ' magic
        let content_str = String::from_utf8_lossy(data);
        
        // Suspicious Packers / Crypters section names
        let packer_indicators = [
            (".upx", "UPX Packer (frequently used for stealth malware delivery)"),
            (".aspack", "Aspack Executable Crypter"),
            (".themida", "Themida / WinLicense Protector"),
            (".vmp", "VMProtect Virtualizer Section"),
            (".mpress", "MPRESS Executable Compressor"),
        ];

        for (sig, desc) in packer_indicators.iter() {
            if content_str.contains(sig) {
                score += 30;
                reasons.push(format!("Packer Detected: {}", desc));
            }
        }

        // Suspicious API Function combinations (Process Injection / Unhooking)
        let injection_apis = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection",
            "QueueUserAPC",
            "SetThreadContext",
        ];

        let mut matched_injection = 0;
        for api in injection_apis.iter() {
            if content_str.contains(api) {
                matched_injection += 1;
            }
        }

        if matched_injection >= 2 {
            score += 40;
            reasons.push(format!("Process Injection APIs Detected ({}/{} matching signatures)", matched_injection, injection_apis.len()));
        }
    }

    // 3. Script Heuristics (.ps1, .vbs, .bat, .js, .sh)
    if lower_name.ends_with(".ps1") || lower_name.ends_with(".bat") || lower_name.ends_with(".vbs") || lower_name.ends_with(".js") {
        let content = String::from_utf8_lossy(data).to_lowercase();

        // Obfuscation indicators
        if content.contains("-enc") || content.contains("-encodedcommand") {
            score += 25;
            reasons.push("Encoded Execution Flag (-EncodedCommand / -enc) detected".to_string());
        }
        if content.contains("[convert]::frombase64string") {
            score += 20;
            reasons.push("Base64 String Deobfuscation Memory Routine".to_string());
        }
        if content.contains("bypass") && content.contains("executionpolicy") {
            score += 15;
            reasons.push("PowerShell ExecutionPolicy Bypass Attempt".to_string());
        }
        if content.contains("downloadstring") && (content.contains("http://") || content.contains("https://")) {
            score += 25;
            reasons.push("Remote Payload Memory Download Routine".to_string());
        }
        if content.contains("net user") && content.contains("/add") {
            score += 35;
            reasons.push("Unauthorized Local Account Creation Command".to_string());
        }
    }

    // 4. Double Extension Traps (e.g. invoice.pdf.exe)
    if lower_name.ends_with(".pdf.exe") || lower_name.ends_with(".docx.exe") || lower_name.ends_with(".xlsx.exe") || lower_name.ends_with(".jpg.exe") {
        score += 50;
        reasons.push("Double Extension Spoofing Trap (e.g. document.pdf.exe)".to_string());
    }

    HeuristicResult {
        is_suspicious: score >= 50,
        score,
        reasons,
    }
}
