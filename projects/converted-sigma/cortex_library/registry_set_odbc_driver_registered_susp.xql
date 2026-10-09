// Title: Potentially Suspicious ODBC Driver Registered
// ID: e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-23
// Tags: attack.credential-access, attack.persistence, attack.t1003
// Description: Detects the registration of a new ODBC driver where the driver is located in a potentially suspicious location
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetObject contains "\\SOFTWARE\\ODBC\\ODBCINST.INI\\" and (TargetObject endswith "\\Driver" or TargetObject endswith "\\Setup") and (Details contains ":\\PerfLogs\\" or Details contains ":\\ProgramData\\" or Details contains ":\\Temp\\" or Details contains ":\\Users\\Public\\" or Details contains ":\\Windows\\Registration\\CRMLog" or Details contains ":\\Windows\\System32\\com\\dmp\\" or Details contains ":\\Windows\\System32\\FxsTmp\\" or Details contains ":\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\" or Details contains ":\\Windows\\System32\\spool\\drivers\\color\\" or Details contains ":\\Windows\\System32\\spool\\PRINTERS\\" or Details contains ":\\Windows\\System32\\spool\\SERVERS\\" or Details contains ":\\Windows\\System32\\Tasks_Migrated\\" or Details contains ":\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\" or Details contains ":\\Windows\\SysWOW64\\com\\dmp\\" or Details contains ":\\Windows\\SysWOW64\\FxsTmp\\" or Details contains ":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\" or Details contains ":\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\" or Details contains ":\\Windows\\Tasks\\" or Details contains ":\\Windows\\Temp\\" or Details contains ":\\Windows\\Tracing\\" or Details contains "\\AppData\\Local\\Temp\\" or Details contains "\\AppData\\Roaming\\"))
