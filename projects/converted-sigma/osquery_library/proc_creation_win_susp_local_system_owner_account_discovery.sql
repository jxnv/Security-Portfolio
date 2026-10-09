-- Title: Local Accounts Discovery
-- ID: 502b42de-4306-40b4-9596-6f590c81f073
-- Status: test
-- Level: low
-- Author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
-- Date: 2019-10-21
-- Tags: attack.discovery, attack.t1033, attack.t1087.001
-- Description: Local accounts, System Owner/User discovery using operating systems utilities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\cmd.exe" AND (CommandLine LIKE '% /c%' AND CommandLine LIKE '%dir %' AND CommandLine LIKE '%\\Users\\%')) AND NOT ((CommandLine LIKE '% rmdir %'))) OR (((Image="*\\net.exe" OR Image="*\\net1.exe") AND CommandLine LIKE '%user%') AND NOT (((CommandLine LIKE '%/domain%' OR CommandLine LIKE '%/add%' OR CommandLine LIKE '%/delete%' OR CommandLine LIKE '%/active%' OR CommandLine LIKE '%/expires%' OR CommandLine LIKE '%/passwordreq%' OR CommandLine LIKE '%/scriptpath%' OR CommandLine LIKE '%/times%' OR CommandLine LIKE '%/workstations%')))) OR ((Image="*\\cmdkey.exe" AND CommandLine LIKE '% /l%') OR (((Image="*\\whoami.exe" OR Image="*\\quser.exe" OR Image="*\\qwinsta.exe")) OR ((OriginalFileName = 'whoami.exe' OR OriginalFileName = 'quser.exe' OR OriginalFileName = 'qwinsta.exe'))) OR (Image="*\\wmic.exe" AND (CommandLine LIKE '%useraccount%' AND CommandLine LIKE '%get%'))))
