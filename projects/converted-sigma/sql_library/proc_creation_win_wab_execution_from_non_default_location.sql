-- Title: Wab Execution From Non Default Location
-- ID: 395907ee-96e5-4666-af2e-2ca91688e151
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-12
-- Tags: attack.execution, attack.stealth
-- Description: Detects execution of wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) from non default locations as seen with bumblebee activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\wab.exe' OR Image ILIKE '%\\wabmig.exe')) AND NOT (((Image ILIKE 'C:\\Windows\\WinSxS\\%' OR Image ILIKE 'C:\\Program Files\\Windows Mail\\%' OR Image ILIKE 'C:\\Program Files (x86)\\Windows Mail\\%'))))
