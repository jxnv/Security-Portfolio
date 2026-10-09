-- Title: Writing Local Admin Share
-- ID: 4aafb0fa-bff5-4b9d-b99e-8093e659c65f
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-01-01
-- Tags: attack.privilege-escalation, attack.persistence, attack.lateral-movement, attack.t1546.002
-- Description: Aversaries may use to interact with a remote network share using Server Message Block (SMB).
-- This technique is used by post-exploitation frameworks.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetFilename ILIKE '%\\\\\\\\127.0.0%' AND TargetFilename ILIKE '%\\ADMIN$\\%'))
