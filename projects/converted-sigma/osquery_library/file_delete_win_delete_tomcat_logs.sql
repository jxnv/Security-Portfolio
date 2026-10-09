-- Title: Tomcat WebServer Logs Deleted
-- ID: 270185ff-5f50-4d6d-a27f-24c3b8c9fef8
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-16
-- Tags: attack.stealth, attack.t1070
-- Description: Detects the deletion of tomcat WebServer logs which may indicate an attempt to destroy forensic evidence
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetFilename LIKE '%\\Tomcat%' AND TargetFilename LIKE '%\\logs\\%') AND (TargetFilename LIKE '%catalina.%' OR TargetFilename LIKE '%_access_log.%' OR TargetFilename LIKE '%localhost.%'))
