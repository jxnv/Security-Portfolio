-- Title: BloodHound Collection Files
-- ID: 02773bed-83bf-469f-b7ff-e676e7d78bab
-- Status: test
-- Level: high
-- Author: C.J. May
-- Date: 2022-08-09
-- Tags: attack.discovery, attack.t1087.001, attack.t1087.002, attack.t1482, attack.t1069.001, attack.t1069.002, attack.execution, attack.t1059.001
-- Description: Detects default file names outputted by the BloodHound collection tool SharpHound
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetFilename ILIKE '%BloodHound.zip' OR TargetFilename ILIKE '%_computers.json' OR TargetFilename ILIKE '%_containers.json' OR TargetFilename ILIKE '%_gpos.json' OR TargetFilename ILIKE '%_groups.json' OR TargetFilename ILIKE '%_ous.json' OR TargetFilename ILIKE '%_users.json')) AND NOT ((Image ILIKE '%\\svchost.exe' AND TargetFilename ILIKE 'C:\\Program Files\\WindowsApps\\Microsoft.%' AND TargetFilename ILIKE '%\\pocket_containers.json')))
