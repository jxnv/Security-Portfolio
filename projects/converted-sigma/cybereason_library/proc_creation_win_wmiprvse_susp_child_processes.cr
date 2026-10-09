// Title: Suspicious WmiPrvSE Child Process
// ID: 8a582fe2-0882-4b89-a82a-da6b2dc32937
// Status: test
// Level: high
// Author: Vadim Khrykov (ThreatIntel), Cyb3rEng, Florian Roth (Nextron Systems)
// Date: 2021-08-23
// Tags: attack.execution, attack.stealth, attack.t1047, attack.t1204.002, attack.t1218.010
// Description: Detects suspicious and uncommon child processes of WmiPrvSE
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\wbem\\WmiPrvSE.exe") AND (((Image="*\\certutil.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\msiexec.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\verclsid.exe" OR Image="*\\wscript.exe")) OR (Image="*\\cmd.exe" AND (CommandLine contains "cscript" OR CommandLine contains "mshta" OR CommandLine contains "powershell" OR CommandLine contains "pwsh" OR CommandLine contains "regsvr32" OR CommandLine contains "rundll32" OR CommandLine contains "wscript"))) AND NOT (((Image="*\\msiexec.exe" AND CommandLine contains "/i ") OR (Image="*\\WerFault.exe") OR (Image="*\\WmiPrvSE.exe"))))
