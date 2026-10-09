// Title: PPL Tampering Via WerFaultSecure
// ID: 1f0b4cac-9c81-41f4-95d0-8475ff46b3e2
// Status: experimental
// Level: high
// Author: Jason (https://github.com/0xbcf)
// Date: 2025-09-23
// Tags: attack.defense-impairment, attack.t1685, attack.credential-access, attack.t1003.001
// Description: Detects potential abuse of WerFaultSecure.exe to dump Protected Process Light (PPL) processes like LSASS or to freeze security solutions (EDR/antivirus).
// This technique is used by tools such as EDR-Freeze and WSASS to bypass PPL protections and access sensitive information or disable security software.
// Distinct command line patterns help identify the specific tool:
// - WSASS usage typically shows: "WSASS.exe WerFaultSecure.exe [PID]" in ParentCommandLine
// - EDR-Freeze usage typically shows: "EDR-Freeze_[version].exe [PID] [timeout]" in ParentCommandLine
// Legitimate debugging operations using WerFaultSecure are rare in production environments and should be investigated.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " /h " AND CommandLine contains " /pid " AND CommandLine contains " /tid " AND CommandLine contains " /encfile " AND CommandLine contains " /cancel " AND CommandLine contains " /type " AND CommandLine contains " 268310")) AND ((Image="*\\WerFaultSecure.exe") OR (OriginalFileName == "WerFaultSecure.exe")))
