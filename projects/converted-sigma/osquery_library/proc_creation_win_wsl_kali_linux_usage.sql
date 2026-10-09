-- Title: WSL Kali-Linux Usage
-- ID: 6f1a11aa-4b8a-4b7f-9e13-4d3e4ff0e0d4
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-10-10
-- Tags: attack.stealth, attack.t1202
-- Description: Detects the use of Kali Linux through Windows Subsystem for Linux
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((((Image LIKE '%:\\Users\\%' AND Image LIKE '%\\AppData\\Local\\packages\\KaliLinux%')) OR ((Image LIKE '%:\\Users\\%' AND Image LIKE '%\\AppData\\Local\\Microsoft\\WindowsApps\\kali.exe%'))) OR (Image LIKE '%:\\Program Files\\WindowsApps\\KaliLinux.%' AND Image="*\\kali.exe")) OR (((((Image LIKE '%\\kali.exe%' OR Image LIKE '%\\KaliLinux%')) OR ((CommandLine LIKE '%Kali.exe%' OR CommandLine LIKE '%Kali-linux%' OR CommandLine LIKE '%kalilinux%'))) AND ((ParentImage="*\\wsl.exe" OR ParentImage="*\\wslhost.exe"))) AND NOT (((CommandLine LIKE '% -i %' OR CommandLine LIKE '% --install %' OR CommandLine LIKE '% --unregister %')))))
