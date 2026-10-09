// Title: Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell
// ID: db885529-903f-4c5d-9864-28fe199e6370
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-11-17
// Tags: attack.discovery, attack.t1033
// Description: Detects usage of the Get-ADComputer cmdlet to collect computer information and output it to a file
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "Get-ADComputer " AND ScriptBlockText contains " -Filter \\*") AND (ScriptBlockText contains " | Select " OR ScriptBlockText contains "Out-File" OR ScriptBlockText contains "Set-Content" OR ScriptBlockText contains "Add-Content"))
