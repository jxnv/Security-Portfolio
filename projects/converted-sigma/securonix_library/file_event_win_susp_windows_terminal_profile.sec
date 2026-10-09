// Title: Windows Terminal Profile Settings Modification By Uncommon Process
// ID: 9b64de98-9db3-4033-bd7a-f51430105f00
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-22
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.015
// Description: Detects the creation or modification of the Windows Terminal Profile settings file "settings.json" by an uncommon process.
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe") AND TargetFilename="*\\AppData\\Local\\Packages\\Microsoft.WindowsTerminal_8wekyb3d8bbwe\\LocalState\\settings.json")
