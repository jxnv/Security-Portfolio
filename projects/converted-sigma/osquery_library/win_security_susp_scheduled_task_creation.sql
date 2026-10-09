-- Title: Suspicious Scheduled Task Creation
-- ID: 3a734d25-df5c-4b99-8034-af1ddb5883a4
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-05
-- Tags: attack.execution, attack.privilege-escalation, attack.persistence, attack.t1053.005
-- Description: Detects suspicious scheduled task creation events. Based on attributes such as paths, commands line flags, etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TaskContent LIKE '%regsvr32%' OR TaskContent LIKE '%rundll32%' OR TaskContent LIKE '%cmd.exe</Command>%' OR TaskContent LIKE '%cmd</Command>%' OR TaskContent LIKE '%<Arguments>/c %' OR TaskContent LIKE '%<Arguments>/k %' OR TaskContent LIKE '%<Arguments>/r %' OR TaskContent LIKE '%powershell%' OR TaskContent LIKE '%pwsh%' OR TaskContent LIKE '%mshta%' OR TaskContent LIKE '%wscript%' OR TaskContent LIKE '%cscript%' OR TaskContent LIKE '%certutil%' OR TaskContent LIKE '%bitsadmin%' OR TaskContent LIKE '%bash.exe%' OR TaskContent LIKE '%bash %' OR TaskContent LIKE '%scrcons%' OR TaskContent LIKE '%wmic %' OR TaskContent LIKE '%wmic.exe%' OR TaskContent LIKE '%forfiles%' OR TaskContent LIKE '%scriptrunner%' OR TaskContent LIKE '%hh.exe%')) AND (EventID = '4698') AND ((TaskContent LIKE '%\\AppData\\Local\\Temp\\%' OR TaskContent LIKE '%\\AppData\\Roaming\\%' OR TaskContent LIKE '%\\Users\\Public\\%' OR TaskContent LIKE '%\\WINDOWS\\Temp\\%' OR TaskContent LIKE '%C:\\Temp\\%' OR TaskContent LIKE '%\\Desktop\\%' OR TaskContent LIKE '%\\Downloads\\%' OR TaskContent LIKE '%\\Temporary Internet%' OR TaskContent LIKE '%C:\\ProgramData\\%' OR TaskContent LIKE '%C:\\Perflogs\\%')))
