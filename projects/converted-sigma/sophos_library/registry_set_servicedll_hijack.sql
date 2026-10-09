-- Title: ServiceDll Hijack
-- ID: 612e47e9-8a59-43a6-b404-f48683f45bd6
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-02-04
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
-- Description: Detects changes to the "ServiceDLL" value related to a service in the registry.
-- This is often used as a method of persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetObject ILIKE '%\\System\\%' AND TargetObject ILIKE '%ControlSet%' AND TargetObject ILIKE '%\\Services\\%') AND TargetObject ILIKE '%\\Parameters\\ServiceDll') AND NOT (((Image = 'C:\\Windows\\system32\\lsass.exe' AND TargetObject ILIKE '%\\Services\\NTDS\\Parameters\\ServiceDll' AND Details = '%%systemroot%%\\system32\\ntdsa.dll') OR (Image = 'C:\\Windows\\System32\\poqexec.exe') OR (Details = 'C:\\Windows\\system32\\spool\\drivers\\x64\\3\\PrintConfig.dll') OR (Image ILIKE '%\\regsvr32.exe' AND TargetObject ILIKE '%\\Services\\PrintNotify\\Parameters\\ServiceDll' AND Details ILIKE 'C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\%' AND Details ILIKE '%\\arm64\\PrintConfig.dll'))) AND NOT ((Image ILIKE '%\\regsvr32.exe' AND Details = 'C:\\Windows\\System32\\STAgent.dll')))
