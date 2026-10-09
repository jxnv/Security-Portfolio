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

SELECT * FROM processes WHERE (NOT (((Image="*.bin" OR Image="*.cgi" OR Image="*.com" OR Image="*.exe" OR Image="*.scr" OR Image="*.tmp"))) AND NOT (((Image LIKE '%:\\$Extend\\$Deleted\\%') OR (Image LIKE '%:\\Windows\\System32\\DriverStore\\FileRepository\\%') OR ((Image = '-' OR Image = '')) OR ((Image = 'System' OR Image = 'Registry' OR Image = 'MemCompression' OR Image = 'vmmem')) OR (Image LIKE '%:\\Windows\\Installer\\MSI%') OR (Image LIKE '%:\\Config.Msi\\%' AND (Image="*.rbf" OR Image="*.rbs")) OR (NOT Image=*) OR ((ParentImage LIKE '%:\\Windows\\Temp\\%') OR (Image LIKE '%:\\Windows\\Temp\\%')))) AND NOT (((ParentImage LIKE '%:\\ProgramData\\Avira\\%') OR (ParentImage = 'C:\\Windows\\System32\\services.exe' AND Image="*com.docker.service") OR (Image LIKE '%:\\Program Files\\Mozilla Firefox\\%') OR (Image="*\\LZMA_EXE") OR ((Image="*:\\Program Files (x86)\\MyQ\\Server\\pcltool.dll" OR Image="*:\\Program Files\\MyQ\\Server\\pcltool.dll")) OR (Image LIKE '%NVIDIA\\NvBackend\\%' AND Image="*.dat") OR ((Image LIKE '%:\\Program Files (x86)\\WINPAKPRO\\%' OR Image LIKE '%:\\Program Files\\WINPAKPRO\\%') AND Image="*.ngn") OR ((Image LIKE '%\\AppData\\Local\\Packages\\%' AND Image LIKE '%\\LocalState\\rootfs\\%')))))
