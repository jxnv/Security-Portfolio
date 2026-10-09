-- Title: Windows Defender Exclusions Added - Registry
-- ID: a982fc9c-6333-4ffb-a51d-addb04e8b529
-- Status: test
-- Level: medium
-- Author: Christian Burkard (Nextron Systems)
-- Date: 2021-07-06
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects the Setting of Windows Defender Exclusions
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (TargetObject ILIKE '%\\Microsoft\\Windows Defender\\Exclusions%')
