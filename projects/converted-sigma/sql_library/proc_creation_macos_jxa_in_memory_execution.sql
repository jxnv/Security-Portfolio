-- Title: JXA In-memory Execution Via OSAScript
-- ID: f1408a58-0e94-4165-b80a-da9f96cf6fc3
-- Status: test
-- Level: high
-- Author: Sohan G (D4rkCiph3r)
-- Date: 2023-01-31
-- Tags: attack.t1059.002, attack.t1059.007, attack.execution
-- Description: Detects possible malicious execution of JXA in-memory via OSAScript
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '% -l %' AND CommandLine ILIKE '%JavaScript%')) OR (CommandLine ILIKE '%.js%')) AND ((CommandLine ILIKE '%osascript%' AND CommandLine ILIKE '% -e %' AND CommandLine ILIKE '%eval%' AND CommandLine ILIKE '%NSData.dataWithContentsOfURL%')))
