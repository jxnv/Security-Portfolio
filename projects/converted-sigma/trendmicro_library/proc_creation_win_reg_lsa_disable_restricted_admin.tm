// Title: RestrictedAdminMode Registry Value Tampering - ProcCreation
// ID: 28ac00d6-22d9-4a3c-927f-bbd770104573
// Status: test
// Level: high
// Author: frack113
// Date: 2023-01-13
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects changes to the "DisableRestrictedAdmin" registry value in order to disable or enable RestrictedAdmin mode.
// RestrictedAdmin mode prevents the transmission of reusable credentials to the remote system to which you connect using Remote Desktop.
// This prevents your credentials from being harvested during the initial connection process if the remote server has been compromise
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "*\\System\\CurrentControlSet\\Control\\Lsa*" AND CommandLine: "*DisableRestrictedAdmin*"))
