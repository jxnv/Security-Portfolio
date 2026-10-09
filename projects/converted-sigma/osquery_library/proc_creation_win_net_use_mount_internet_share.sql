-- Title: Windows Internet Hosted WebDav Share Mount Via Net.EXE
-- ID: 7e6237fe-3ddb-438f-9381-9bf9de5af8d0
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-21
-- Tags: attack.lateral-movement, attack.t1021.002
-- Description: Detects when an internet hosted webdav share is mounted using the "net.exe" utility
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% use %' AND CommandLine LIKE '% http%')) AND (((Image="*\\net.exe" OR Image="*\\net1.exe")) OR ((OriginalFileName = 'net.exe' OR OriginalFileName = 'net1.exe'))))
