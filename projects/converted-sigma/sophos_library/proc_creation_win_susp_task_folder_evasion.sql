-- Title: Tasks Folder Evasion
-- ID: cc4e02ba-9c06-48e2-b09e-2500cace9ae0
-- Status: test
-- Level: high
-- Author: Sreeman
-- Date: 2020-01-13
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
-- Description: The Tasks folder in system32 and syswow64 are globally writable paths.
-- Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application
-- in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%echo %' OR CommandLine ILIKE '%copy %' OR CommandLine ILIKE '%type %' OR CommandLine ILIKE '%file createnew%')) AND ((CommandLine ILIKE '% C:\\Windows\\System32\\Tasks\\%' OR CommandLine ILIKE '% C:\\Windows\\SysWow64\\Tasks\\%')))
