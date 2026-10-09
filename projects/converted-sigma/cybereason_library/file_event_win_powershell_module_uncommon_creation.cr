// Title: PowerShell Module File Created By Non-PowerShell Process
// ID: e3845023-ca9a-4024-b2b2-5422156d5527
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-09
// Tags: attack.persistence
// Description: Detects the creation of a new PowerShell module ".psm1", ".psd1", ".dll", ".ps1", etc. by a non-PowerShell process
// Converted by: Sigma Universal SIEM/EDR CLI

(((TargetFilename contains "\\WindowsPowerShell\\Modules\\" OR TargetFilename contains "\\PowerShell\\7\\Modules\\")) AND NOT ((((Image == "C:\\Windows\\System32\\msiexec.exe" OR Image == "C:\\Windows\\SysWOW64\\msiexec.exe")) OR ((Image="*:\\Program Files\\PowerShell\\7-preview\\pwsh.exe" OR Image="*:\\Program Files\\PowerShell\\7\\pwsh.exe" OR Image="*:\\Windows\\System32\\poqexec.exe" OR Image="*:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe" OR Image="*:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" OR Image="*:\\Windows\\SysWOW64\\poqexec.exe" OR Image="*:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell_ise.exe" OR Image="*:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe")))))
