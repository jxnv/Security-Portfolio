-- Title: Outlook Security Settings Updated - Registry
-- ID: c3cefdf4-6703-4e1c-bad8-bf422fc5015a
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-28
-- Tags: attack.persistence, attack.t1137
-- Description: Detects changes to the registry values related to outlook security settings
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Office\\%' AND TargetObject ILIKE '%\\Outlook\\Security\\%')) AND NOT (((Image ILIKE 'C:\\Program Files\\Microsoft Office\\%' OR Image ILIKE 'C:\\Program Files (x86)\\Microsoft Office\\%') AND Image ILIKE '%\\OUTLOOK.EXE')))
