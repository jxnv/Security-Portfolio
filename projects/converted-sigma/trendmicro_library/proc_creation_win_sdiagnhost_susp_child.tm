// Title: Sdiagnhost Calling Suspicious Child Process
// ID: f3d39c45-de1a-4486-a687-ab126124f744
// Status: test
// Level: high
// Author: Nextron Systems, @Kostastsale
// Date: 2022-06-01
// Tags: attack.stealth, attack.t1036, attack.t1218
// Description: Detects sdiagnhost.exe calling a suspicious child process (e.g. used in exploits for Follina / CVE-2022-30190)
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\sdiagnhost.exe" AND (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe" OR Image="*\\mshta.exe" OR Image="*\\cscript.exe" OR Image="*\\wscript.exe" OR Image="*\\taskkill.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\calc.exe")) AND NOT (((Image="*\\cmd.exe" AND CommandLine: "*bits*") OR (Image="*\\powershell.exe" AND (CommandLine="*-noprofile -" OR CommandLine="*-noprofile")))))
