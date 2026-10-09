// Title: AADInternals PowerShell Cmdlets Execution - ProccessCreation
// ID: c86500e9-a645-4680-98d7-f882c70c1ea3
// Status: test
// Level: high
// Author: Austin Songer (@austinsonger), Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2022-12-23
// Tags: attack.execution, attack.reconnaissance, attack.discovery, attack.credential-access, attack.impact
// Description: Detects ADDInternals Cmdlet execution. A tool for administering Azure AD and Office 365. Which can be abused by threat actors to attack Azure AD or Office 365.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*Add-AADInt*" OR CommandLine: "*ConvertTo-AADInt*" OR CommandLine: "*Disable-AADInt*" OR CommandLine: "*Enable-AADInt*" OR CommandLine: "*Export-AADInt*" OR CommandLine: "*Find-AADInt*" OR CommandLine: "*Get-AADInt*" OR CommandLine: "*Grant-AADInt*" OR CommandLine: "*Initialize-AADInt*" OR CommandLine: "*Install-AADInt*" OR CommandLine: "*Invoke-AADInt*" OR CommandLine: "*Join-AADInt*" OR CommandLine: "*New-AADInt*" OR CommandLine: "*Open-AADInt*" OR CommandLine: "*Read-AADInt*" OR CommandLine: "*Register-AADInt*" OR CommandLine: "*Remove-AADInt*" OR CommandLine: "*Reset-AADInt*" OR CommandLine: "*Resolve-AADInt*" OR CommandLine: "*Restore-AADInt*" OR CommandLine: "*Save-AADInt*" OR CommandLine: "*Search-AADInt*" OR CommandLine: "*Send-AADInt*" OR CommandLine: "*Set-AADInt*" OR CommandLine: "*Start-AADInt*" OR CommandLine: "*Unprotect-AADInt*" OR CommandLine: "*Update-AADInt*")) AND (((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName: "PowerShell.Exe" OR OriginalFileName: "pwsh.dll"))))
