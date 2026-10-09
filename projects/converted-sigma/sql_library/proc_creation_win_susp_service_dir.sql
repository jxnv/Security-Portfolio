-- Title: Suspicious Service Binary Directory
-- ID: 883faa95-175a-4e22-8181-e5761aeb373c
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-03-09
-- Tags: attack.stealth, attack.t1202
-- Description: Detects a service binary running in a suspicious directory
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\Users\\Public\\%' OR Image ILIKE '%\\$Recycle.bin%' OR Image ILIKE '%\\Users\\All Users\\%' OR Image ILIKE '%\\Users\\Default\\%' OR Image ILIKE '%\\Users\\Contacts\\%' OR Image ILIKE '%\\Users\\Searches\\%' OR Image ILIKE '%C:\\Perflogs\\%' OR Image ILIKE '%\\config\\systemprofile\\%' OR Image ILIKE '%\\Windows\\Fonts\\%' OR Image ILIKE '%\\Windows\\IME\\%' OR Image ILIKE '%\\Windows\\addins\\%') AND (ParentImage ILIKE '%\\services.exe' OR ParentImage ILIKE '%\\svchost.exe'))
