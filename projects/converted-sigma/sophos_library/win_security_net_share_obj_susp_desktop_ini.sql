-- Title: Windows Network Access Suspicious desktop.ini Action
-- ID: 35bc7e28-ee6b-492f-ab04-da58fcf6402e
-- Status: test
-- Level: medium
-- Author: Tim Shelton (HAWK.IO)
-- Date: 2021-12-06
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.009
-- Description: Detects unusual processes accessing desktop.ini remotely over network share, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 5145 AND ObjectType = 'File' AND RelativeTargetName ILIKE '%\\desktop.ini' AND (AccessList ILIKE '%WriteData%' OR AccessList ILIKE '%DELETE%' OR AccessList ILIKE '%WriteDAC%' OR AccessList ILIKE '%AppendData%' OR AccessList ILIKE '%AddSubdirectory%'))
