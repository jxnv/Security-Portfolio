-- Title: Computer System Reconnaissance Via Wmic.EXE
-- ID: 9d7ca793-f6bd-471c-8d0f-11e68b2f0d2f
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-08
-- Tags: attack.discovery, attack.execution, attack.t1047
-- Description: Detects execution of wmic utility with the "computersystem" flag in order to obtain information about the machine such as the domain, username, model, etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%computersystem%') AND ((Image ILIKE '%\\wmic.exe') OR (OriginalFileName = 'wmic.exe')))
