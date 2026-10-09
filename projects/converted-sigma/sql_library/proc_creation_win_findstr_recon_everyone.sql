-- Title: Permission Misconfiguration Reconnaissance Via Findstr.EXE
-- ID: 47e4bab7-c626-47dc-967b-255608c9a920
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-12
-- Tags: attack.credential-access, attack.t1552.006
-- Description: Detects usage of findstr with the "EVERYONE" or "BUILTIN" keywords.
-- This was seen being used in combination with "icacls" and other utilities to spot misconfigured files or folders permissions.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((CommandLine ILIKE '%\"Everyone\"%' OR CommandLine ILIKE '%'Everyone'%' OR CommandLine ILIKE '%\"BUILTIN\\\\\"%' OR CommandLine ILIKE '%'BUILTIN\\'%')) AND (((Image ILIKE '%\\find.exe' OR Image ILIKE '%\\findstr.exe')) OR ((OriginalFileName = 'FIND.EXE' OR OriginalFileName = 'FINDSTR.EXE')))) OR ((CommandLine ILIKE '%icacls %' AND CommandLine ILIKE '%findstr %' AND CommandLine ILIKE '%Everyone%')))
