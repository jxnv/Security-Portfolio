-- Title: User Added To Highly Privileged Group
-- ID: 10fb649c-3600-4d37-b1e6-56ea90bb7e09
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-02-23
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1098
-- Description: Detects addition of users to highly privileged groups via "Net" or "Add-LocalGroupMember".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Group Policy Creator Owners%' OR CommandLine LIKE '%Schema Admins%')) AND (((CommandLine LIKE '%localgroup %' AND CommandLine LIKE '% /add%')) OR ((CommandLine LIKE '%Add-LocalGroupMember %' AND CommandLine LIKE '% -Group %'))))
