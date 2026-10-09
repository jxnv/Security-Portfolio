-- Title: Suspicious Service Binary Directory
-- ID: 883faa95-175a-4e22-8181-e5761aeb373c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-03-09
-- Tags: attack.stealth, attack.t1202
-- Description: Detects a service binary running in a suspicious directory
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image LIKE '%\\Users\\Public\\%' OR Image LIKE '%\\$Recycle.bin%' OR Image LIKE '%\\Users\\All Users\\%' OR Image LIKE '%\\Users\\Default\\%' OR Image LIKE '%\\Users\\Contacts\\%' OR Image LIKE '%\\Users\\Searches\\%' OR Image LIKE '%C:\\Perflogs\\%' OR Image LIKE '%\\config\\systemprofile\\%' OR Image LIKE '%\\Windows\\Fonts\\%' OR Image LIKE '%\\Windows\\IME\\%' OR Image LIKE '%\\Windows\\addins\\%') AND (ParentImage="*\\services.exe" OR ParentImage="*\\svchost.exe"))
