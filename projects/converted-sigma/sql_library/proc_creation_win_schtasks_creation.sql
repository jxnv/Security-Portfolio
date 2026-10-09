-- Title: Scheduled Task Creation Via Schtasks.EXE
-- ID: 92626ddd-662c-49e3-ac59-f6535f12d189
-- Status: test
-- Level: low
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-01-16
-- Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.t1053.005, attack.s0111, car.2013-08-001, stp.1u
-- Description: Detects the creation of scheduled tasks by user accounts via the "schtasks" utility.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\schtasks.exe' AND CommandLine ILIKE '% /create %') AND NOT (((User ILIKE '%AUTHORI%' OR User ILIKE '%AUTORI%'))) AND NOT (((ParentImage = 'C:\\Program Files\\Microsoft Office\\root\\integration\\integrator.exe' OR ParentImage = 'C:\\Program Files (x86)\\Microsoft Office\\root\\integration\\integrator.exe') AND (Image = 'C:\\Windows\\System32\\schtasks.exe' OR Image = 'C:\\Windows\\SysWOW64\\schtasks.exe') AND CommandLine ILIKE '%Microsoft\\Office\\Office Performance Monitor%')))
