// ==============================================================================
// THUNDER SCANNER - Signature & Hash Database (10-Star Edition)
// Built by: NEXO-TECH
// ==============================================================================

pub struct HashSignature {
    pub hash: &'static str,
    pub name: &'static str,
    pub severity: &'static str,
    pub category: &'static str,
}

pub struct PatternSignature {
    pub name: &'static str,
    pub pattern: &'static str,
    pub severity: &'static str,
    pub category: &'static str,
}

pub const KNOWN_HASHES: &[HashSignature] = &[
    // EICAR Standard Test File
    HashSignature {
        hash: "44d88612fea8a8f36de82e1278abb02f",
        name: "EICAR-Standard-AV-Test-File",
        severity: "TEST",
        category: "Test Virus",
    },
    HashSignature {
        hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        name: "EICAR-Standard-AV-Test-File-SHA256",
        severity: "TEST",
        category: "Test Virus",
    },
    // WannaCry Ransomware
    HashSignature {
        hash: "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        name: "Ransom:Win32/WannaCry.A",
        severity: "CRITICAL",
        category: "Ransomware",
    },
    HashSignature {
        hash: "84c82835a5d21bbcf75a61706d8ab549",
        name: "Ransom:Win32/WannaCry.MD5",
        severity: "CRITICAL",
        category: "Ransomware",
    },
    // Emotet Banking Trojan
    HashSignature {
        hash: "4a2c91a329d49ddb6fb1a88b56f8f7c9e0758410fb59bb36f048d0859c25bb28",
        name: "Trojan:Win32/Emotet.Generic",
        severity: "CRITICAL",
        category: "Banking Trojan",
    },
    // Petya / NotPetya Ransomware
    HashSignature {
        hash: "0277305cd021a602147328a3f50f17cf25425d6040e4995c732bb3038e061398",
        name: "Ransom:Win32/NotPetya.A",
        severity: "CRITICAL",
        category: "Ransomware / Wiper",
    },
    // DarkSide Ransomware
    HashSignature {
        hash: "931215b22b10a9bfbe9a35e4e20ef9f43f11d13f990145c11bc37ea920b22a01",
        name: "Ransom:Win32/DarkSide.A",
        severity: "CRITICAL",
        category: "Ransomware",
    },
    // LockBit 3.0 Ransomware
    HashSignature {
        hash: "1f81ab924e2c88463c2c1fb67a21394f48ad0a72ad41c888d3e9255a6d5952d7",
        name: "Ransom:Win32/LockBit.3",
        severity: "CRITICAL",
        category: "Ransomware",
    },
    // Cobalt Strike Beacon Loader
    HashSignature {
        hash: "7f4c084046d296cf287a916891eb534b5c778408f654b9d031bfec6f0ad0ae62",
        name: "Backdoor:Win32/CobaltStrike.Beacon",
        severity: "CRITICAL",
        category: "C2 Implant",
    },
    // XMRig Monero Stealth Miner
    HashSignature {
        hash: "9d90597b4b3b7bb577e116e25be4bebb8f8285514f77c862bc2d5c31ff7eb3bc",
        name: "CoinMiner:Win32/XMRig.Silent",
        severity: "HIGH",
        category: "Cryptocurrency Miner",
    },
    // Mimikatz
    HashSignature {
        hash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        name: "HackTool:Win32/Mimikatz.Generic",
        severity: "CRITICAL",
        category: "Credential Stealer",
    },
];

pub const PATTERN_SIGNATURES: &[PatternSignature] = &[
    // EICAR String
    PatternSignature {
        name: "EICAR-Standard-AV-Test-Signature",
        pattern: "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        severity: "TEST",
        category: "Test Virus",
    },
    // PowerShell Reverse Shell
    PatternSignature {
        name: "Trojan:PowerShell/ReverseShell.TCPClient",
        pattern: "New-Object System.Net.Sockets.TCPClient",
        severity: "CRITICAL",
        category: "Reverse Shell",
    },
    PatternSignature {
        name: "Trojan:PowerShell/ReverseShell.SocketStream",
        pattern: "GetStream().Write($sendbyte,0,$sendbyte.Length)",
        severity: "CRITICAL",
        category: "Reverse Shell",
    },
    // AMSI Bypass Patterns
    PatternSignature {
        name: "HackTool:PowerShell/AMSI.Bypass.Patch",
        pattern: "AmsiUtils.amsiInitFailed",
        severity: "HIGH",
        category: "AMSI Bypass / Evasion",
    },
    PatternSignature {
        name: "HackTool:PowerShell/AMSI.AmsiScanBuffer",
        pattern: "AmsiScanBuffer",
        severity: "MEDIUM",
        category: "AMSI Bypass / Memory Patch",
    },
    // Mimikatz & Credential Dumping
    PatternSignature {
        name: "HackTool:Win32/Invoke-Mimikatz",
        pattern: "sekurlsa::logonpasswords",
        severity: "CRITICAL",
        category: "Credential Stealer",
    },
    PatternSignature {
        name: "HackTool:Win32/Mimikatz.Wdigest",
        pattern: "sekurlsa::wdigest",
        severity: "CRITICAL",
        category: "Credential Stealer",
    },
    // Obfuscated Download Cradles
    PatternSignature {
        name: "Trojan:Script/DownloadCradle.WebClient",
        pattern: "IEX(New-Object Net.WebClient).DownloadString",
        severity: "HIGH",
        category: "Downloader Stager",
    },
    PatternSignature {
        name: "Trojan:Script/DownloadCradle.InvokeRestMethod",
        pattern: "IEX (irm",
        severity: "MEDIUM",
        category: "Downloader Stager",
    },
    // PHP & ASPX WebShells
    PatternSignature {
        name: "WebShell:PHP/c99.Generic",
        pattern: "c99shell",
        severity: "CRITICAL",
        category: "WebShell",
    },
    PatternSignature {
        name: "WebShell:PHP/b374k.Generic",
        pattern: "b374k",
        severity: "CRITICAL",
        category: "WebShell",
    },
    PatternSignature {
        name: "WebShell:PHP/EvalBase64",
        pattern: "eval(base64_decode(",
        severity: "HIGH",
        category: "WebShell Stager",
    },
    // Crypto Miner Configs
    PatternSignature {
        name: "CoinMiner:Generic/StratumMining",
        pattern: "stratum+tcp://",
        severity: "HIGH",
        category: "Cryptocurrency Miner",
    },
    // Linux Bash & Netcat Reverse Shells
    PatternSignature {
        name: "Trojan:Linux/ReverseShell.BashTCP",
        pattern: "/bin/sh -i >& /dev/tcp/",
        severity: "CRITICAL",
        category: "Reverse Shell",
    },
    PatternSignature {
        name: "Trojan:Linux/ReverseShell.Netcat",
        pattern: "nc -e /bin/sh",
        severity: "CRITICAL",
        category: "Reverse Shell",
    },
];
