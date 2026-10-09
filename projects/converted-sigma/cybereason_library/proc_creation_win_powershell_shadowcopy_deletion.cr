// Title: Deletion of Volume Shadow Copies via WMI with PowerShell
// ID: 21ff4ca9-f13a-41ad-b828-0077b2af2e40
// Status: test
// Level: high
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-20
// Tags: attack.impact, attack.t1490
// Description: Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains ".Delete()" OR CommandLine contains "Remove-WmiObject" OR CommandLine contains "rwmi" OR CommandLine contains "Remove-CimInstance" OR CommandLine contains "rcim")) AND ((CommandLine contains "Get-WmiObject" OR CommandLine contains "gwmi" OR CommandLine contains "Get-CimInstance" OR CommandLine contains "gcim")) AND (CommandLine contains "Win32_ShadowCopy"))
