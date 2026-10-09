-- Title: Execution of Suspicious File Type Extension
-- ID: c09dad97-1c78-4f71-b127-7edb2b8e491a
-- Status: test
-- Level: medium
-- Author: Max Altgelt (Nextron Systems)
-- Date: 2021-12-09
-- Tags: attack.stealth
-- Description: Detects whether the image specified in a process creation event doesn't refer to an ".exe" (or other known executable extension) file. This can be caused by process ghosting or other unorthodox methods to start a process.
-- This rule might require some initial baselining to align with some third party tooling in the user environment.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (NOT (((Image ILIKE '%.bin' OR Image ILIKE '%.cgi' OR Image ILIKE '%.com' OR Image ILIKE '%.exe' OR Image ILIKE '%.scr' OR Image ILIKE '%.tmp'))) AND NOT (((Image ILIKE '%:\\$Extend\\$Deleted\\%') OR (Image ILIKE '%:\\Windows\\System32\\DriverStore\\FileRepository\\%') OR ((Image = '-' OR Image = '')) OR ((Image = 'System' OR Image = 'Registry' OR Image = 'MemCompression' OR Image = 'vmmem')) OR (Image ILIKE '%:\\Windows\\Installer\\MSI%') OR (Image ILIKE '%:\\Config.Msi\\%' AND (Image ILIKE '%.rbf' OR Image ILIKE '%.rbs')) OR (Image IS NULL) OR ((ParentImage ILIKE '%:\\Windows\\Temp\\%') OR (Image ILIKE '%:\\Windows\\Temp\\%')))) AND NOT (((ParentImage ILIKE '%:\\ProgramData\\Avira\\%') OR (ParentImage = 'C:\\Windows\\System32\\services.exe' AND Image ILIKE '%com.docker.service') OR (Image ILIKE '%:\\Program Files\\Mozilla Firefox\\%') OR (Image ILIKE '%\\LZMA_EXE') OR ((Image ILIKE '%:\\Program Files (x86)\\MyQ\\Server\\pcltool.dll' OR Image ILIKE '%:\\Program Files\\MyQ\\Server\\pcltool.dll')) OR (Image ILIKE '%NVIDIA\\NvBackend\\%' AND Image ILIKE '%.dat') OR ((Image ILIKE '%:\\Program Files (x86)\\WINPAKPRO\\%' OR Image ILIKE '%:\\Program Files\\WINPAKPRO\\%') AND Image ILIKE '%.ngn') OR ((Image ILIKE '%\\AppData\\Local\\Packages\\%' AND Image ILIKE '%\\LocalState\\rootfs\\%')))))
