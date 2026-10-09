// Title: Suspicious PowerShell Mailbox Export to Share - PS
// ID: 4a241dea-235b-4a7e-8d76-50d817b146c4
// Status: test
// Level: critical
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-26
// Tags: attack.exfiltration
// Description: Detects usage of the powerShell New-MailboxExportRequest Cmdlet to exports a mailbox to a remote or local share, as used in ProxyShell exploitations
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "New-MailboxExportRequest" and ScriptBlockText contains " -Mailbox " and ScriptBlockText contains " -FilePath \\\\\\\\"))
