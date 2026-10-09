-- Title: Suspicious Scheduled Task Creation
-- ID: 3a734d25-df5c-4b99-8034-af1ddb5883a4
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-05
-- Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.t1053.005
-- Description: Detects suspicious scheduled task creation events. Based on attributes such as paths, commands line flags, etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TaskContent ILIKE '%regsvr32%' OR TaskContent ILIKE '%rundll32%' OR TaskContent ILIKE '%cmd.exe</Command>%' OR TaskContent ILIKE '%cmd</Command>%' OR TaskContent ILIKE '%<Arguments>/c %' OR TaskContent ILIKE '%<Arguments>/k %' OR TaskContent ILIKE '%<Arguments>/r %' OR TaskContent ILIKE '%powershell%' OR TaskContent ILIKE '%pwsh%' OR TaskContent ILIKE '%mshta%' OR TaskContent ILIKE '%wscript%' OR TaskContent ILIKE '%cscript%' OR TaskContent ILIKE '%certutil%' OR TaskContent ILIKE '%bitsadmin%' OR TaskContent ILIKE '%bash.exe%' OR TaskContent ILIKE '%bash %' OR TaskContent ILIKE '%scrcons%' OR TaskContent ILIKE '%wmic %' OR TaskContent ILIKE '%wmic.exe%' OR TaskContent ILIKE '%forfiles%' OR TaskContent ILIKE '%scriptrunner%' OR TaskContent ILIKE '%hh.exe%')) AND (EventID = 4698) AND ((TaskContent ILIKE '%\\AppData\\Local\\Temp\\%' OR TaskContent ILIKE '%\\AppData\\Roaming\\%' OR TaskContent ILIKE '%\\Users\\Public\\%' OR TaskContent ILIKE '%\\WINDOWS\\Temp\\%' OR TaskContent ILIKE '%C:\\Temp\\%' OR TaskContent ILIKE '%\\Desktop\\%' OR TaskContent ILIKE '%\\Downloads\\%' OR TaskContent ILIKE '%\\Temporary Internet%' OR TaskContent ILIKE '%C:\\ProgramData\\%' OR TaskContent ILIKE '%C:\\Perflogs\\%')))
