-- Title: Potentially Suspicious ODBC Driver Registered
-- ID: e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-23
-- Tags: attack.credential-access, attack.persistence, attack.t1003
-- Description: Detects the registration of a new ODBC driver where the driver is located in a potentially suspicious location
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (TargetObject LIKE '%\\SOFTWARE\\ODBC\\ODBCINST.INI\\%' AND (TargetObject="*\\Driver" OR TargetObject="*\\Setup") AND (Details LIKE '%:\\PerfLogs\\%' OR Details LIKE '%:\\ProgramData\\%' OR Details LIKE '%:\\Temp\\%' OR Details LIKE '%:\\Users\\Public\\%' OR Details LIKE '%:\\Windows\\Registration\\CRMLog%' OR Details LIKE '%:\\Windows\\System32\\com\\dmp\\%' OR Details LIKE '%:\\Windows\\System32\\FxsTmp\\%' OR Details LIKE '%:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\%' OR Details LIKE '%:\\Windows\\System32\\spool\\drivers\\color\\%' OR Details LIKE '%:\\Windows\\System32\\spool\\PRINTERS\\%' OR Details LIKE '%:\\Windows\\System32\\spool\\SERVERS\\%' OR Details LIKE '%:\\Windows\\System32\\Tasks_Migrated\\%' OR Details LIKE '%:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR Details LIKE '%:\\Windows\\SysWOW64\\com\\dmp\\%' OR Details LIKE '%:\\Windows\\SysWOW64\\FxsTmp\\%' OR Details LIKE '%:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\%' OR Details LIKE '%:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR Details LIKE '%:\\Windows\\Tasks\\%' OR Details LIKE '%:\\Windows\\Temp\\%' OR Details LIKE '%:\\Windows\\Tracing\\%' OR Details LIKE '%\\AppData\\Local\\Temp\\%' OR Details LIKE '%\\AppData\\Roaming\\%'))
