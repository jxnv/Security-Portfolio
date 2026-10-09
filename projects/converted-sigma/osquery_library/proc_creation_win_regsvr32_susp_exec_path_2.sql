-- Title: Regsvr32 Execution From Highly Suspicious Location
-- ID: 327ff235-94eb-4f06-b9de-aaee571324be
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-26
-- Tags: attack.stealth, attack.t1218.010
-- Description: Detects execution of regsvr32 where the DLL is located in a highly suspicious locations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\regsvr32.exe") OR (OriginalFileName = 'REGSVR32.EXE')) AND (((CommandLine LIKE '%:\\PerfLogs\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%\\Windows\\Registration\\CRMLog%' OR CommandLine LIKE '%\\Windows\\System32\\com\\dmp\\%' OR CommandLine LIKE '%\\Windows\\System32\\FxsTmp\\%' OR CommandLine LIKE '%\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\%' OR CommandLine LIKE '%\\Windows\\System32\\spool\\drivers\\color\\%' OR CommandLine LIKE '%\\Windows\\System32\\spool\\PRINTERS\\%' OR CommandLine LIKE '%\\Windows\\System32\\spool\\SERVERS\\%' OR CommandLine LIKE '%\\Windows\\System32\\Tasks_Migrated\\%' OR CommandLine LIKE '%\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR CommandLine LIKE '%\\Windows\\SysWOW64\\com\\dmp\\%' OR CommandLine LIKE '%\\Windows\\SysWOW64\\FxsTmp\\%' OR CommandLine LIKE '%\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\%' OR CommandLine LIKE '%\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR CommandLine LIKE '%\\Windows\\Tasks\\%' OR CommandLine LIKE '%\\Windows\\Tracing\\%')) OR (((CommandLine LIKE '% \"C:\\%' OR CommandLine LIKE '% C:\\%' OR CommandLine LIKE '% 'C:\\%' OR CommandLine LIKE '%D:\\%')) AND NOT (((CommandLine LIKE '%C:\\Program Files (x86)\\%' OR CommandLine LIKE '%C:\\Program Files\\%' OR CommandLine LIKE '%C:\\ProgramData\\%' OR CommandLine LIKE '%C:\\Users\\%' OR CommandLine LIKE '% C:\\Windows\\%' OR CommandLine LIKE '% \"C:\\Windows\\%' OR CommandLine LIKE '% 'C:\\Windows\\%'))))) AND NOT (((CommandLine = '') OR (NOT CommandLine=*))))
