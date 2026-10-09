-- Title: Suspicious Schtasks Schedule Types
-- ID: 24c8392b-aa3c-46b7-a545-43f71657fe98
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-09
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects scheduled task creations or modification on a suspicious schedule type
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\schtasks.exe") OR (OriginalFileName = 'schtasks.exe')) AND ((CommandLine LIKE '% ONLOGON %' OR CommandLine LIKE '% ONSTART %' OR CommandLine LIKE '% ONCE %' OR CommandLine LIKE '% ONIDLE %'))) AND NOT (((CommandLine LIKE '%NT AUT%' OR CommandLine LIKE '% SYSTEM%' OR CommandLine LIKE '%HIGHEST%'))))
