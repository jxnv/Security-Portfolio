-- Title: Persistence Via Sticky Key Backdoor
-- ID: 1070db9a-3e5d-412e-8e7b-7183b616e1b3
-- Status: test
-- Level: critical
-- Author: Sreeman
-- Date: 2020-02-18
-- Tags: attack.persistence, attack.t1546.008, attack.privilege-escalation
-- Description: By replacing the sticky keys executable with the local admins CMD executable, an attacker is able to access a privileged windows console session without authenticating to the system.
-- When the sticky keys are "activated" the privilleged shell is launched.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%copy %' AND CommandLine ILIKE '%/y %' AND CommandLine ILIKE '%C:\\windows\\system32\\cmd.exe C:\\windows\\system32\\sethc.exe%'))
