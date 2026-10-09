-- Title: UAC Bypass via ICMLuaUtil
-- ID: 49f2f17b-b4c8-4172-a68b-d5bf95d05130
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Elastic (idea)
-- Date: 2022-09-13
-- Tags: attack.privilege-escalation, attack.t1548.002
-- Description: Detects the pattern of UAC Bypass using ICMLuaUtil Elevated COM interface
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\dllhost.exe" AND (ParentCommandLine LIKE '%/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}%' OR ParentCommandLine LIKE '%/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}%')) AND NOT (((Image="*\\WerFault.exe") OR (OriginalFileName = 'WerFault.exe'))))
