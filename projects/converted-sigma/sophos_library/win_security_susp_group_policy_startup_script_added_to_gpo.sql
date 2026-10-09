-- Title: Startup/Logon Script Added to Group Policy Object
-- ID: 123e4e6d-b123-48f8-b261-7214938acaf0
-- Status: test
-- Level: medium
-- Author: Elastic, Josh Nickels, Marius Rothenbücher
-- Date: 2024-09-06
-- Tags: attack.persistence, attack.privilege-escalation, attack.defense-impairment, attack.t1484.001, attack.t1547
-- Description: Detects the modification of Group Policy Objects (GPO) to add a startup/logon script to users or computer objects.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((EventID = 5136 OR EventID = 5145)) AND ((((AttributeLDAPDisplayName = 'gPCMachineExtensionNames' OR AttributeLDAPDisplayName = 'gPCUserExtensionNames') AND AttributeValue ILIKE '%42B5FAAE-6536-11D2-AE5A-0000F87571E3%') AND ((AttributeValue ILIKE '%40B6664F-4972-11D1-A7CA-0000F87571E3%' OR AttributeValue ILIKE '%40B66650-4972-11D1-A7CA-0000F87571E3%'))) OR (ShareName ILIKE '%\\SYSVOL' AND (RelativeTargetName ILIKE '%\\scripts.ini' OR RelativeTargetName ILIKE '%\\psscripts.ini') AND AccessList ILIKE '%%%4417%')))
