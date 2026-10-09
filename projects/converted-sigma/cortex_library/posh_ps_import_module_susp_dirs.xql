// Title: Import PowerShell Modules From Suspicious Directories
// ID: 21f9162c-5f5d-4b01-89a8-b705bd7d10ab
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-07
// Tags: attack.execution, attack.t1059.001
// Description: Detects powershell scripts that import modules from suspicious directories
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "Import-Module \"$Env:Temp\\" or ScriptBlockText contains "Import-Module '$Env:Temp\\" or ScriptBlockText contains "Import-Module $Env:Temp\\" or ScriptBlockText contains "Import-Module \"$Env:Appdata\\" or ScriptBlockText contains "Import-Module '$Env:Appdata\\" or ScriptBlockText contains "Import-Module $Env:Appdata\\" or ScriptBlockText contains "Import-Module C:\\Users\\Public\\" or ScriptBlockText contains "ipmo \"$Env:Temp\\" or ScriptBlockText contains "ipmo '$Env:Temp\\" or ScriptBlockText contains "ipmo $Env:Temp\\" or ScriptBlockText contains "ipmo \"$Env:Appdata\\" or ScriptBlockText contains "ipmo '$Env:Appdata\\" or ScriptBlockText contains "ipmo $Env:Appdata\\" or ScriptBlockText contains "ipmo C:\\Users\\Public\\"))
