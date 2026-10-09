-- Title: Suspicious Git Clone - Linux
-- ID: cfec9d29-64ec-4a0f-9ffe-0fdb856d5446
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-03
-- Tags: attack.reconnaissance, attack.t1593.003
-- Description: Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/git" AND CommandLine LIKE '% clone %') AND ((CommandLine LIKE '%exploit%' OR CommandLine LIKE '%Vulns%' OR CommandLine LIKE '%vulnerability%' OR CommandLine LIKE '%RCE%' OR CommandLine LIKE '%RemoteCodeExecution%' OR CommandLine LIKE '%Invoke-%' OR CommandLine LIKE '%CVE-%' OR CommandLine LIKE '%poc-%' OR CommandLine LIKE '%ProofOfConcept%' OR CommandLine LIKE '%proxyshell%' OR CommandLine LIKE '%log4shell%' OR CommandLine LIKE '%eternalblue%' OR CommandLine LIKE '%eternal-blue%' OR CommandLine LIKE '%MS17-%')))
