// Title: Change PowerShell Policies to an Insecure Level - PowerShell
// ID: 61d0475c-173f-4844-86f7-f3eebae1c66b
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-10-20
// Tags: attack.execution, attack.t1059.001
// Description: Detects changing the PowerShell script execution policy to a potentially insecure level using the "Set-ExecutionPolicy" cmdlet.
// Converted by: Sigma Universal SIEM/EDR CLI

(((ScriptBlockText contains "Set-ExecutionPolicy") AND ((ScriptBlockText contains "Unrestricted" OR ScriptBlockText contains "bypass"))) AND NOT (((ScriptBlockText contains "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')" OR ScriptBlockText contains "(New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')"))))
