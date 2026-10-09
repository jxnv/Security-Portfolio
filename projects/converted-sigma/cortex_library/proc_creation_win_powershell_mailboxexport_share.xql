// Title: Suspicious PowerShell Mailbox Export to Share
// ID: 889719ef-dd62-43df-86c3-768fb08dc7c0
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2021-08-07
// Tags: attack.exfiltration
// Description: Detects usage of the powerShell New-MailboxExportRequest Cmdlet to exports a mailbox to a remote or local share, as used in ProxyShell exploitations
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "New-MailboxExportRequest" and action_process_image_command_line contains " -Mailbox " and action_process_image_command_line contains " -FilePath \\\\\\\\"))
