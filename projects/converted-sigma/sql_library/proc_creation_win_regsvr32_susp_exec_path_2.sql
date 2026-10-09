-- Title: Regsvr32 Execution From Highly Suspicious Location
-- ID: 327ff235-94eb-4f06-b9de-aaee571324be
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-26
-- Tags: attack.stealth, attack.t1218.010
-- Description: Detects execution of regsvr32 where the DLL is located in a highly suspicious locations
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\regsvr32.exe') OR (OriginalFileName = 'REGSVR32.EXE')) AND (((CommandLine ILIKE '%:\\PerfLogs\\%' OR CommandLine ILIKE '%:\\Temp\\%' OR CommandLine ILIKE '%\\Windows\\Registration\\CRMLog%' OR CommandLine ILIKE '%\\Windows\\System32\\com\\dmp\\%' OR CommandLine ILIKE '%\\Windows\\System32\\FxsTmp\\%' OR CommandLine ILIKE '%\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\%' OR CommandLine ILIKE '%\\Windows\\System32\\spool\\drivers\\color\\%' OR CommandLine ILIKE '%\\Windows\\System32\\spool\\PRINTERS\\%' OR CommandLine ILIKE '%\\Windows\\System32\\spool\\SERVERS\\%' OR CommandLine ILIKE '%\\Windows\\System32\\Tasks_Migrated\\%' OR CommandLine ILIKE '%\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR CommandLine ILIKE '%\\Windows\\SysWOW64\\com\\dmp\\%' OR CommandLine ILIKE '%\\Windows\\SysWOW64\\FxsTmp\\%' OR CommandLine ILIKE '%\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\%' OR CommandLine ILIKE '%\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\%' OR CommandLine ILIKE '%\\Windows\\Tasks\\%' OR CommandLine ILIKE '%\\Windows\\Tracing\\%')) OR (((CommandLine ILIKE '% \"C:\\%' OR CommandLine ILIKE '% C:\\%' OR CommandLine ILIKE '% 'C:\\%' OR CommandLine ILIKE '%D:\\%')) AND NOT (((CommandLine ILIKE '%C:\\Program Files (x86)\\%' OR CommandLine ILIKE '%C:\\Program Files\\%' OR CommandLine ILIKE '%C:\\ProgramData\\%' OR CommandLine ILIKE '%C:\\Users\\%' OR CommandLine ILIKE '% C:\\Windows\\%' OR CommandLine ILIKE '% \"C:\\Windows\\%' OR CommandLine ILIKE '% 'C:\\Windows\\%'))))) AND NOT (((CommandLine = '') OR (CommandLine IS NULL))))
