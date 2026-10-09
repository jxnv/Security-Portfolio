// Title: AADInternals PowerShell Cmdlets Execution - PsScript
// ID: 91e69562-2426-42ce-a647-711b8152ced6
// Status: test
// Level: high
// Author: Austin Songer (@austinsonger), Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2022-12-23
// Tags: attack.execution, attack.reconnaissance, attack.discovery, attack.credential-access, attack.impact
// Description: Detects ADDInternals Cmdlet execution. A tool for administering Azure AD and Office 365. Which can be abused by threat actors to attack Azure AD or Office 365.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "Add-AADInt" or ScriptBlockText contains "ConvertTo-AADInt" or ScriptBlockText contains "Disable-AADInt" or ScriptBlockText contains "Enable-AADInt" or ScriptBlockText contains "Export-AADInt" or ScriptBlockText contains "Find-AADInt" or ScriptBlockText contains "Get-AADInt" or ScriptBlockText contains "Grant-AADInt" or ScriptBlockText contains "Initialize-AADInt" or ScriptBlockText contains "Install-AADInt" or ScriptBlockText contains "Invoke-AADInt" or ScriptBlockText contains "Join-AADInt" or ScriptBlockText contains "New-AADInt" or ScriptBlockText contains "Open-AADInt" or ScriptBlockText contains "Read-AADInt" or ScriptBlockText contains "Register-AADInt" or ScriptBlockText contains "Remove-AADInt" or ScriptBlockText contains "Reset-AADInt" or ScriptBlockText contains "Resolve-AADInt" or ScriptBlockText contains "Restore-AADInt" or ScriptBlockText contains "Save-AADInt" or ScriptBlockText contains "Search-AADInt" or ScriptBlockText contains "Send-AADInt" or ScriptBlockText contains "Set-AADInt" or ScriptBlockText contains "Start-AADInt" or ScriptBlockText contains "Unprotect-AADInt" or ScriptBlockText contains "Update-AADInt"))
