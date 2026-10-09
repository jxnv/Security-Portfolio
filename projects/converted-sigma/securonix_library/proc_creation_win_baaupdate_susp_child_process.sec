// Title: Suspicious BitLocker Access Agent Update Utility Execution
// ID: 9f38c1db-e2ae-40bf-81d0-5b68f73fb512
// Status: experimental
// Level: high
// Author: andrewdanis, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-10-18
// Tags: attack.stealth, attack.t1218, attack.lateral-movement, attack.t1021.003
// Description: Detects the execution of the BitLocker Access Agent Update Utility (baaupdate.exe) which is not a common parent process for other processes.
// Suspicious child processes spawned by baaupdate.exe could indicate an attempt at lateral movement via BitLocker DCOM & COM Hijacking.
// Converted by: Sigma Universal SIEM/EDR CLI

(ParentImage="*\\baaupdate.exe" AND (Image="*\\bitsadmin.exe" OR Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\powershell.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\schtasks.exe" OR Image="*\\wmic.exe" OR Image="*\\wscript.exe"))
