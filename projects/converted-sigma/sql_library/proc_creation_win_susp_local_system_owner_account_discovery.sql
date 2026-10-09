-- Title: Local Accounts Discovery
-- ID: 502b42de-4306-40b4-9596-6f590c81f073
-- Status: test
-- Level: low
-- Author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
-- Date: 2019-10-21
-- Tags: attack.discovery, attack.t1033, attack.t1087.001
-- Description: Local accounts, System Owner/User discovery using operating systems utilities
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\cmd.exe' AND (CommandLine ILIKE '% /c%' AND CommandLine ILIKE '%dir %' AND CommandLine ILIKE '%\\Users\\%')) AND NOT ((CommandLine ILIKE '% rmdir %'))) OR (((Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe') AND CommandLine ILIKE '%user%') AND NOT (((CommandLine ILIKE '%/domain%' OR CommandLine ILIKE '%/add%' OR CommandLine ILIKE '%/delete%' OR CommandLine ILIKE '%/active%' OR CommandLine ILIKE '%/expires%' OR CommandLine ILIKE '%/passwordreq%' OR CommandLine ILIKE '%/scriptpath%' OR CommandLine ILIKE '%/times%' OR CommandLine ILIKE '%/workstations%')))) OR ((Image ILIKE '%\\cmdkey.exe' AND CommandLine ILIKE '% /l%') OR (((Image ILIKE '%\\whoami.exe' OR Image ILIKE '%\\quser.exe' OR Image ILIKE '%\\qwinsta.exe')) OR ((OriginalFileName = 'whoami.exe' OR OriginalFileName = 'quser.exe' OR OriginalFileName = 'qwinsta.exe'))) OR (Image ILIKE '%\\wmic.exe' AND (CommandLine ILIKE '%useraccount%' AND CommandLine ILIKE '%get%'))))
