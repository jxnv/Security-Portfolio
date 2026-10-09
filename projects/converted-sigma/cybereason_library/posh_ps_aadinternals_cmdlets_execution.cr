// Title: AADInternals PowerShell Cmdlets Execution - PsScript
// ID: 91e69562-2426-42ce-a647-711b8152ced6
// Status: test
// Level: high
// Author: Austin Songer (@austinsonger), Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2022-12-23
// Tags: attack.execution, attack.reconnaissance, attack.discovery, attack.credential-access, attack.impact
// Description: Detects ADDInternals Cmdlet execution. A tool for administering Azure AD and Office 365. Which can be abused by threat actors to attack Azure AD or Office 365.
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "Add-AADInt" OR ScriptBlockText contains "ConvertTo-AADInt" OR ScriptBlockText contains "Disable-AADInt" OR ScriptBlockText contains "Enable-AADInt" OR ScriptBlockText contains "Export-AADInt" OR ScriptBlockText contains "Find-AADInt" OR ScriptBlockText contains "Get-AADInt" OR ScriptBlockText contains "Grant-AADInt" OR ScriptBlockText contains "Initialize-AADInt" OR ScriptBlockText contains "Install-AADInt" OR ScriptBlockText contains "Invoke-AADInt" OR ScriptBlockText contains "Join-AADInt" OR ScriptBlockText contains "New-AADInt" OR ScriptBlockText contains "Open-AADInt" OR ScriptBlockText contains "Read-AADInt" OR ScriptBlockText contains "Register-AADInt" OR ScriptBlockText contains "Remove-AADInt" OR ScriptBlockText contains "Reset-AADInt" OR ScriptBlockText contains "Resolve-AADInt" OR ScriptBlockText contains "Restore-AADInt" OR ScriptBlockText contains "Save-AADInt" OR ScriptBlockText contains "Search-AADInt" OR ScriptBlockText contains "Send-AADInt" OR ScriptBlockText contains "Set-AADInt" OR ScriptBlockText contains "Start-AADInt" OR ScriptBlockText contains "Unprotect-AADInt" OR ScriptBlockText contains "Update-AADInt"))
