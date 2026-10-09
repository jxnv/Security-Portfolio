// Title: Remote Thread Creation Via PowerShell In Uncommon Target
// ID: 99b97608-3e21-4bfe-8217-2a127c396a0e
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2018-06-25
// Tags: attack.execution, attack.stealth, attack.t1218.011, attack.t1059.001
// Description: Detects the creation of a remote thread from a Powershell process in an uncommon target process
// Converted by: Sigma Universal SIEM/EDR CLI

((SourceImage="*\\powershell.exe" OR SourceImage="*\\pwsh.exe") AND (TargetImage="*\\rundll32.exe" OR TargetImage="*\\regsvr32.exe"))
