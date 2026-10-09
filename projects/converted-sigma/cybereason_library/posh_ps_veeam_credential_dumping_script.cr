// Title: Veeam Backup Servers Credential Dumping Script Execution
// ID: 976d6e6f-a04b-4900-9713-0134a353e38b
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-04
// Tags: attack.credential-access
// Description: Detects execution of a PowerShell script that contains calls to the "Veeam.Backup" class, in order to dump stored credentials.
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "[Credentials]" AND ScriptBlockText contains "[Veeam.Backup.Common.ProtectedStorage]::GetLocalString" AND ScriptBlockText contains "Invoke-Sqlcmd" AND ScriptBlockText contains "Veeam Backup and Replication"))
