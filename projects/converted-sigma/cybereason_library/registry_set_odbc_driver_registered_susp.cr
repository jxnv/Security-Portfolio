// Title: Potentially Suspicious ODBC Driver Registered
// ID: e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-23
// Tags: attack.credential-access, attack.persistence, attack.t1003
// Description: Detects the registration of a new ODBC driver where the driver is located in a potentially suspicious location
// Converted by: Sigma Universal SIEM/EDR CLI

(TargetObject contains "\\SOFTWARE\\ODBC\\ODBCINST.INI\\" AND (TargetObject="*\\Driver" OR TargetObject="*\\Setup") AND (Details contains ":\\PerfLogs\\" OR Details contains ":\\ProgramData\\" OR Details contains ":\\Temp\\" OR Details contains ":\\Users\\Public\\" OR Details contains ":\\Windows\\Registration\\CRMLog" OR Details contains ":\\Windows\\System32\\com\\dmp\\" OR Details contains ":\\Windows\\System32\\FxsTmp\\" OR Details contains ":\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\" OR Details contains ":\\Windows\\System32\\spool\\drivers\\color\\" OR Details contains ":\\Windows\\System32\\spool\\PRINTERS\\" OR Details contains ":\\Windows\\System32\\spool\\SERVERS\\" OR Details contains ":\\Windows\\System32\\Tasks_Migrated\\" OR Details contains ":\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\" OR Details contains ":\\Windows\\SysWOW64\\com\\dmp\\" OR Details contains ":\\Windows\\SysWOW64\\FxsTmp\\" OR Details contains ":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\" OR Details contains ":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\" OR Details contains ":\\Windows\\Tasks\\" OR Details contains ":\\Windows\\Temp\\" OR Details contains ":\\Windows\\Tracing\\" OR Details contains "\\AppData\\Local\\Temp\\" OR Details contains "\\AppData\\Roaming\\"))
