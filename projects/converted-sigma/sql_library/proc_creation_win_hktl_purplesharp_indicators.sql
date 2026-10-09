-- Title: HackTool - PurpleSharp Execution
-- ID: ff23ffbc-3378-435e-992f-0624dcf93ab4
-- Status: test
-- Level: critical
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-06-18
-- Tags: attack.t1587, attack.resource-development
-- Description: Detects the execution of the PurpleSharp adversary simulation tool
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%xyz123456.exe%' OR CommandLine ILIKE '%PurpleSharp%')) OR ((Image ILIKE '%\\purplesharp%') OR (OriginalFileName = 'PurpleSharp.exe')))
