-- Title: Curl Web Request With Potential Custom User-Agent
-- ID: 85de1f22-d189-44e4-8239-dc276b45379b
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-07-27
-- Tags: attack.execution
-- Description: Detects execution of "curl.exe" with a potential custom "User-Agent". Attackers can leverage this to download or exfiltrate data via "curl" to a domain that only accept specific "User-Agent" strings
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\curl.exe") OR (OriginalFileName = 'curl.exe')) AND ((CommandLine=regex("\\s-H\\s")) OR (CommandLine LIKE '%--header%')) AND (CommandLine LIKE '%User-Agent:%'))
