-- Title: Tomcat WebServer Logs Deleted
-- ID: 270185ff-5f50-4d6d-a27f-24c3b8c9fef8
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-16
-- Tags: attack.stealth, attack.t1070
-- Description: Detects the deletion of tomcat WebServer logs which may indicate an attempt to destroy forensic evidence
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE '%\\Tomcat%' AND TargetFilename ILIKE '%\\logs\\%') AND (TargetFilename ILIKE '%catalina.%' OR TargetFilename ILIKE '%_access_log.%' OR TargetFilename ILIKE '%localhost.%'))
