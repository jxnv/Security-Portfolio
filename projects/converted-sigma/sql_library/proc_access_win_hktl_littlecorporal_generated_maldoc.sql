-- Title: HackTool - LittleCorporal Generated Maldoc Injection
-- ID: 7bdde3bf-2a42-4c39-aa31-a92b3e17afac
-- Status: test
-- Level: high
-- Author: Christian Burkard (Nextron Systems)
-- Date: 2021-08-09
-- Tags: attack.execution, attack.privilege-escalation, attack.stealth, attack.t1204.002, attack.t1055.003
-- Description: Detects the process injection of a LittleCorporal generated Maldoc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (SourceImage ILIKE '%\\winword.exe' AND (CallTrace ILIKE '%:\\Windows\\Microsoft.NET\\Framework64\\v2.%' AND CallTrace ILIKE '%UNKNOWN%'))
