-- Title: WSL Kali-Linux Usage
-- ID: 6f1a11aa-4b8a-4b7f-9e13-4d3e4ff0e0d4
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-10-10
-- Tags: attack.stealth, attack.t1202
-- Description: Detects the use of Kali Linux through Windows Subsystem for Linux
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((((Image ILIKE '%:\\Users\\%' AND Image ILIKE '%\\AppData\\Local\\packages\\KaliLinux%')) OR ((Image ILIKE '%:\\Users\\%' AND Image ILIKE '%\\AppData\\Local\\Microsoft\\WindowsApps\\kali.exe%'))) OR (Image ILIKE '%:\\Program Files\\WindowsApps\\KaliLinux.%' AND Image ILIKE '%\\kali.exe')) OR (((((Image ILIKE '%\\kali.exe%' OR Image ILIKE '%\\KaliLinux%')) OR ((CommandLine ILIKE '%Kali.exe%' OR CommandLine ILIKE '%Kali-linux%' OR CommandLine ILIKE '%kalilinux%'))) AND ((ParentImage ILIKE '%\\wsl.exe' OR ParentImage ILIKE '%\\wslhost.exe'))) AND NOT (((CommandLine ILIKE '% -i %' OR CommandLine ILIKE '% --install %' OR CommandLine ILIKE '% --unregister %')))))
