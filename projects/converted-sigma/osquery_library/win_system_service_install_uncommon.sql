-- Title: Uncommon Service Installation Image Path
-- ID: 26481afe-db26-4228-b264-25a29fe6efc7
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-18
-- Tags: attack.persistence, attack.privilege-escalation, car.2013-09-005, attack.t1543.003
-- Description: Detects uncommon service installation commands by looking at suspicious or uncommon image path values containing references to encoded powershell commands, temporary paths, etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Provider_Name = 'Service Control Manager' AND EventID = '7045') AND (((ImagePath LIKE '%\\\\\\\\.\\\\pipe%' OR ImagePath LIKE '%\\Users\\Public\\%' OR ImagePath LIKE '%\\Windows\\Temp\\%')) OR ((ImagePath LIKE '% -e%') AND ((ImagePath LIKE '% aQBlAHgA%' OR ImagePath LIKE '% aWV4I%' OR ImagePath LIKE '% IAB%' OR ImagePath LIKE '% JAB%' OR ImagePath LIKE '% PAA%' OR ImagePath LIKE '% SQBFAFgA%' OR ImagePath LIKE '% SUVYI%')))) AND NOT ((ImagePath="C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\*")) AND NOT ((ImagePath="C:\\WINDOWS\\TEMP\\thor10-remote\\thor64.exe*")))
