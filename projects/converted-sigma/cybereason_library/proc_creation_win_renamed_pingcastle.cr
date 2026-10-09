// Title: Renamed PingCastle Binary Execution
// ID: 2433a154-bb3d-42e4-86c3-a26bdac91c45
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
// Date: 2024-01-11
// Tags: attack.execution, attack.stealth, attack.t1059, attack.t1202
// Description: Detects the execution of a renamed "PingCastle" binary based on the PE metadata fields.
// Converted by: Sigma Universal SIEM/EDR CLI

((((OriginalFileName == "PingCastleReporting.exe" OR OriginalFileName == "PingCastleCloud.exe" OR OriginalFileName == "PingCastle.exe")) OR ((CommandLine contains "--scanner aclcheck" OR CommandLine contains "--scanner antivirus" OR CommandLine contains "--scanner computerversion" OR CommandLine contains "--scanner foreignusers" OR CommandLine contains "--scanner laps_bitlocker" OR CommandLine contains "--scanner localadmin" OR CommandLine contains "--scanner nullsession" OR CommandLine contains "--scanner nullsession-trust" OR CommandLine contains "--scanner oxidbindings" OR CommandLine contains "--scanner remote" OR CommandLine contains "--scanner share" OR CommandLine contains "--scanner smb" OR CommandLine contains "--scanner smb3querynetwork" OR CommandLine contains "--scanner spooler" OR CommandLine contains "--scanner startup" OR CommandLine contains "--scanner zerologon")) OR (CommandLine contains "--no-enum-limit") OR ((CommandLine contains "--healthcheck" AND CommandLine contains "--level Full")) OR ((CommandLine contains "--healthcheck" AND CommandLine contains "--server "))) AND NOT (((Image="*\\PingCastleReporting.exe" OR Image="*\\PingCastleCloud.exe" OR Image="*\\PingCastle.exe"))))
