-- Title: Suspicious Git Clone
-- ID: aef9d1f1-7396-4e92-a927-4567c7a495c1
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-03
-- Tags: attack.reconnaissance, attack.t1593.003
-- Description: Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% clone %' OR CommandLine LIKE '%git-remote-https %')) AND (((Image="*\\git.exe" OR Image="*\\git-remote-https.exe")) OR (OriginalFileName = 'git.exe')) AND ((CommandLine LIKE '%exploit%' OR CommandLine LIKE '%Vulns%' OR CommandLine LIKE '%vulnerability%' OR CommandLine LIKE '%RemoteCodeExecution%' OR CommandLine LIKE '%Invoke-%' OR CommandLine LIKE '%CVE-%' OR CommandLine LIKE '%poc-%' OR CommandLine LIKE '%ProofOfConcept%' OR CommandLine LIKE '%proxyshell%' OR CommandLine LIKE '%log4shell%' OR CommandLine LIKE '%eternalblue%' OR CommandLine LIKE '%eternal-blue%' OR CommandLine LIKE '%MS17-%')))
