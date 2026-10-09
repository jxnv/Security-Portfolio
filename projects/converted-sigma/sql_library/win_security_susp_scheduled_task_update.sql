-- Title: Suspicious Scheduled Task Update
-- ID: 614cf376-6651-47c4-9dcc-6b9527f749f4
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-05
-- Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.t1053.005
-- Description: Detects update to a scheduled task event that contain suspicious keywords.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TaskContentNew ILIKE '%regsvr32%' OR TaskContentNew ILIKE '%rundll32%' OR TaskContentNew ILIKE '%cmd.exe</Command>%' OR TaskContentNew ILIKE '%cmd</Command>%' OR TaskContentNew ILIKE '%<Arguments>/c %' OR TaskContentNew ILIKE '%<Arguments>/k %' OR TaskContentNew ILIKE '%<Arguments>/r %' OR TaskContentNew ILIKE '%powershell%' OR TaskContentNew ILIKE '%pwsh%' OR TaskContentNew ILIKE '%mshta%' OR TaskContentNew ILIKE '%wscript%' OR TaskContentNew ILIKE '%cscript%' OR TaskContentNew ILIKE '%certutil%' OR TaskContentNew ILIKE '%bitsadmin%' OR TaskContentNew ILIKE '%bash.exe%' OR TaskContentNew ILIKE '%bash %' OR TaskContentNew ILIKE '%scrcons%' OR TaskContentNew ILIKE '%wmic %' OR TaskContentNew ILIKE '%wmic.exe%' OR TaskContentNew ILIKE '%forfiles%' OR TaskContentNew ILIKE '%scriptrunner%' OR TaskContentNew ILIKE '%hh.exe%')) AND (EventID = 4702) AND ((TaskContentNew ILIKE '%\\AppData\\Local\\Temp\\%' OR TaskContentNew ILIKE '%\\AppData\\Roaming\\%' OR TaskContentNew ILIKE '%\\Users\\Public\\%' OR TaskContentNew ILIKE '%\\WINDOWS\\Temp\\%' OR TaskContentNew ILIKE '%C:\\Temp\\%' OR TaskContentNew ILIKE '%\\Desktop\\%' OR TaskContentNew ILIKE '%\\Downloads\\%' OR TaskContentNew ILIKE '%\\Temporary Internet%' OR TaskContentNew ILIKE '%C:\\ProgramData\\%' OR TaskContentNew ILIKE '%C:\\Perflogs\\%')))
