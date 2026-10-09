// Title: Potentially Suspicious ODBC Driver Registered
// ID: e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-23
// Tags: attack.credential-access, attack.persistence, attack.t1003
// Description: Detects the registration of a new ODBC driver where the driver is located in a potentially suspicious location
// Converted by: Sigma Universal SIEM/EDR CLI

(TargetObject: "*\\SOFTWARE\\ODBC\\ODBCINST.INI\\*" AND (TargetObject="*\\Driver" OR TargetObject="*\\Setup") AND (Details: "*:\\PerfLogs\\*" OR Details: "*:\\ProgramData\\*" OR Details: "*:\\Temp\\*" OR Details: "*:\\Users\\Public\\*" OR Details: "*:\\Windows\\Registration\\CRMLog*" OR Details: "*:\\Windows\\System32\\com\\dmp\\*" OR Details: "*:\\Windows\\System32\\FxsTmp\\*" OR Details: "*:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\*" OR Details: "*:\\Windows\\System32\\spool\\drivers\\color\\*" OR Details: "*:\\Windows\\System32\\spool\\PRINTERS\\*" OR Details: "*:\\Windows\\System32\\spool\\SERVERS\\*" OR Details: "*:\\Windows\\System32\\Tasks_Migrated\\*" OR Details: "*:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\*" OR Details: "*:\\Windows\\SysWOW64\\com\\dmp\\*" OR Details: "*:\\Windows\\SysWOW64\\FxsTmp\\*" OR Details: "*:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\*" OR Details: "*:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\*" OR Details: "*:\\Windows\\Tasks\\*" OR Details: "*:\\Windows\\Temp\\*" OR Details: "*:\\Windows\\Tracing\\*" OR Details: "*\\AppData\\Local\\Temp\\*" OR Details: "*\\AppData\\Roaming\\*"))
