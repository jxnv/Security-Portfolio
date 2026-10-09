// Title: Delete Volume Shadow Copies Via WMI With PowerShell
// ID: 87df9ee1-5416-453a-8a08-e8d4a51e9ce1
// Status: stable
// Level: high
// Author: frack113
// Date: 2021-06-03
// Tags: attack.impact, attack.t1490
// Description: Shadow Copies deletion using operating systems utilities via PowerShell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Data contains "Get-WmiObject" and Data contains "Win32_ShadowCopy") and (Data contains "Delete()" or Data contains "Remove-WmiObject"))
