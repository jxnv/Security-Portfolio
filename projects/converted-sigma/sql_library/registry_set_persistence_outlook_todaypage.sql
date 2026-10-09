-- Title: Potential Persistence Via Outlook Today Page
-- ID: 487bb375-12ef-41f6-baae-c6a1572b4dd1
-- Status: test
-- Level: high
-- Author: Tobias Michalski (Nextron Systems), David Bertho (@dbertho) & Eirik Sveen (@0xSV1), Storebrand
-- Date: 2021-06-10
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects potential persistence activity via outlook today page.
-- An attacker can set a custom page to execute arbitrary code and link to it via the registry values "URL" and "UserDefinedUrl".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetObject ILIKE '%Software\\Microsoft\\Office\\%' AND TargetObject ILIKE '%\\Outlook\\Today\\%')) AND ((TargetObject ILIKE '%\\Stamp' AND Details = 'DWORD (0x00000001)') OR ((TargetObject ILIKE '%\\URL' OR TargetObject ILIKE '%\\UserDefinedUrl'))) AND NOT (((Image ILIKE 'C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\%' OR Image ILIKE 'C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\Updates\\%') AND Image ILIKE '%\\OfficeClickToRun.exe')))
