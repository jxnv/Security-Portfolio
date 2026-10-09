-- Title: HackTool - CrackMapExec File Indicators
-- ID: 736ffa74-5f6f-44ca-94ef-1c0df4f51d2a
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-03-11
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects file creation events with filename patterns used by CrackMapExec.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetFilename="C:\\Windows\\Temp\\*") AND (((TargetFilename=regex("\\\\[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.txt$")) OR (TargetFilename=regex("\\\\[a-zA-Z]{8}\\.tmp$"))) OR ((TargetFilename="*\\temp.ps1" OR TargetFilename="*\\msol.ps1"))))
