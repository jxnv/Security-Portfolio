-- Title: Outlook Macro Execution Without Warning Setting Enabled
-- ID: e3b50fa5-3c3f-444e-937b-0a99d33731cd
-- Status: test
-- Level: high
-- Author: @ScoubiMtl
-- Date: 2021-04-05
-- Tags: attack.privilege-escalation, attack.persistence, attack.command-and-control, attack.t1137, attack.t1008, attack.t1546
-- Description: Detects the modification of Outlook security setting to allow unprompted execution of macros.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (TargetObject="*\\Outlook\\Security\\Level" AND Details LIKE '%0x00000001%')
