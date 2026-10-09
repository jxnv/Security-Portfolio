-- Title: Suspicious Schtasks Schedule Types
-- ID: 24c8392b-aa3c-46b7-a545-43f71657fe98
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-09
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
-- Description: Detects scheduled task creations or modification on a suspicious schedule type
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\schtasks.exe') OR (OriginalFileName = 'schtasks.exe')) AND ((CommandLine ILIKE '% ONLOGON %' OR CommandLine ILIKE '% ONSTART %' OR CommandLine ILIKE '% ONCE %' OR CommandLine ILIKE '% ONIDLE %'))) AND NOT (((CommandLine ILIKE '%NT AUT%' OR CommandLine ILIKE '% SYSTEM%' OR CommandLine ILIKE '%HIGHEST%'))))
