// Title: History File Deletion
// ID: 1182f3b3-e716-4efa-99ab-d2685d04360f
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.impact, attack.t1565.001
// Description: Detects events in which a history file gets deleted, e.g. the ~/bash_history to remove traces of malicious activity
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*/rm" OR Image="*/unlink" OR Image="*/shred")) AND (((CommandLine: "*/.bash_history*" OR CommandLine: "*/.zsh_history*")) OR ((CommandLine="*_history" OR CommandLine="*.history" OR CommandLine="*zhistory"))))
