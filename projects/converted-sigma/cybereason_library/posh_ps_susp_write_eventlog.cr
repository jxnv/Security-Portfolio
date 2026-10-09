// Title: PowerShell Write-EventLog Usage
// ID: 35f41cd7-c98e-469f-8a02-ec4ba0cc7a7e
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-16
// Tags: attack.defense-impairment
// Description: Detects usage of the "Write-EventLog" cmdlet with 'RawData' flag. The cmdlet can be levreage to write malicious payloads to the EventLog and then retrieve them later for later use
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "Write-EventLog" AND ScriptBlockText contains "-RawData "))
