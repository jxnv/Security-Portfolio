-- Title: Odbcconf.EXE Suspicious DLL Location
-- ID: 6b65c28e-11f3-46cb-902a-68f2cafaf474
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-22
-- Tags: attack.stealth, attack.t1218.008
-- Description: Detects execution of "odbcconf" where the path of the DLL being registered is located in a potentially suspicious location.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%:\\PerfLogs\\%' OR CommandLine LIKE '%:\\ProgramData\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Users\\Public\\%' OR CommandLine LIKE '%:\\Windows\\Registration\\CRMLog%' OR CommandLine LIKE '%:\\Windows\\System32\\com\\dmp\\%' OR CommandLine LIKE '%:\\Windows\\System32\\FxsTmp\\%' OR CommandLine LIKE '%:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\%' OR CommandLine LIKE '%:\\Windows\\System32\\spool\\drivers\\color\\%' OR CommandLine LIKE '%:\\Windows\\System32\\spool\\PRINTERS\\%' OR CommandLine LIKE '%:\\Windows\\System32\\spool\\SERVERS\\%' OR CommandLine LIKE '%:\\Windows\\System32\\Tasks_Migrated\\%' OR CommandLine LIKE '%:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR CommandLine LIKE '%:\\Windows\\SysWOW64\\com\\dmp\\%' OR CommandLine LIKE '%:\\Windows\\SysWOW64\\FxsTmp\\%' OR CommandLine LIKE '%:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\%' OR CommandLine LIKE '%:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR CommandLine LIKE '%:\\Windows\\Tasks\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%:\\Windows\\Tracing\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Roaming\\%')) AND ((Image="*\\odbcconf.exe") OR (OriginalFileName = 'odbcconf.exe')))
