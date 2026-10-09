-- Title: PUA - Nmap/Zenmap Execution
-- ID: f6ecd1cf-19b8-4488-97f6-00f0924991a3
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-10
-- Tags: attack.discovery, attack.t1046
-- Description: Detects usage of namp/zenmap. Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\nmap.exe" OR Image="*\\zennmap.exe")) OR ((OriginalFileName = 'nmap.exe' OR OriginalFileName = 'zennmap.exe')))
