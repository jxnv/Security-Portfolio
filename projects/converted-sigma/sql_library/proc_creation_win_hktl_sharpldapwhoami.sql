-- Title: HackTool - SharpLdapWhoami Execution
-- ID: d9367cbb-c2e0-47ce-bdc0-128cb6da898d
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-08-29
-- Tags: attack.discovery, attack.t1033, car.2016-03-001
-- Description: Detects SharpLdapWhoami, a whoami alternative that queries the LDAP service on a domain controller
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% /method:ntlm' OR CommandLine ILIKE '% /method:kerb' OR CommandLine ILIKE '% /method:nego' OR CommandLine ILIKE '% /m:nego' OR CommandLine ILIKE '% /m:ntlm' OR CommandLine ILIKE '% /m:kerb')) OR (Image ILIKE '%\\SharpLdapWhoami.exe') OR ((OriginalFileName ILIKE '%SharpLdapWhoami%') OR (Product = 'SharpLdapWhoami')))
