-- Title: Disable Windows Security Center Notifications
-- ID: 3ae1a046-f7db-439d-b7ce-b8b366b81fa6
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-08-19
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detect set UseActionCenterExperience to 0 to disable the Windows security center notification
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (TargetObject="*Windows\\CurrentVersion\\ImmersiveShell\\UseActionCenterExperience" AND Details = 'DWORD (0x00000000)')
