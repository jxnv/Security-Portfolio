-- Title: Uncommon Service Installation Image Path
-- ID: 26481afe-db26-4228-b264-25a29fe6efc7
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-18
-- Tags: attack.persistence, attack.privilege-escalation, car.2013-09-005, attack.t1543.003
-- Description: Detects uncommon service installation commands by looking at suspicious or uncommon image path values containing references to encoded powershell commands, temporary paths, etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Provider_Name = 'Service Control Manager' AND EventID = 7045) AND (((ImagePath ILIKE '%\\\\\\\\.\\\\pipe%' OR ImagePath ILIKE '%\\Users\\Public\\%' OR ImagePath ILIKE '%\\Windows\\Temp\\%')) OR ((ImagePath ILIKE '% -e%') AND ((ImagePath ILIKE '% aQBlAHgA%' OR ImagePath ILIKE '% aWV4I%' OR ImagePath ILIKE '% IAB%' OR ImagePath ILIKE '% JAB%' OR ImagePath ILIKE '% PAA%' OR ImagePath ILIKE '% SQBFAFgA%' OR ImagePath ILIKE '% SUVYI%')))) AND NOT ((ImagePath ILIKE 'C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\%')) AND NOT ((ImagePath ILIKE 'C:\\WINDOWS\\TEMP\\thor10-remote\\thor64.exe%')))
