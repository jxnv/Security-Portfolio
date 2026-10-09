-- Title: Suspicious Windows Trace ETW Session Tamper Via Logman.EXE
-- ID: cd1f961e-0b96-436b-b7c6-38da4583ec00
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-02-11
-- Tags: attack.defense-impairment, attack.t1685, attack.t1685.005
-- Description: Detects the execution of "logman" utility in order to disable or delete Windows trace sessions
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%stop %' OR CommandLine ILIKE '%delete %')) AND ((Image ILIKE '%\\logman.exe') OR (OriginalFileName = 'Logman.exe')) AND ((CommandLine ILIKE '%Circular Kernel Context Logger%' OR CommandLine ILIKE '%EventLog-%' OR CommandLine ILIKE '%SYSMON TRACE%' OR CommandLine ILIKE '%SysmonDnsEtwSession%')))
