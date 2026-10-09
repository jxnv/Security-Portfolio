-- Title: Always Install Elevated Windows Installer
-- ID: cd951fdc-4b2f-47f5-ba99-a33bf61e3770
-- Status: test
-- Level: medium
-- Author: Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community
-- Date: 2020-10-13
-- Tags: attack.privilege-escalation, attack.t1548.002
-- Description: Detects Windows Installer service (msiexec.exe) trying to install MSI packages with SYSTEM privilege
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((Image ILIKE '%\\Windows\\Installer\\%' AND Image ILIKE '%msi%') AND Image ILIKE '%tmp') OR (Image ILIKE '%\\msiexec.exe' AND (IntegrityLevel = 'System' OR IntegrityLevel = 'S-1-16-16384'))) AND ((User ILIKE '%AUTHORI%' OR User ILIKE '%AUTORI%')) AND NOT ((((ParentImage ILIKE 'C:\\Program Files\\Avast Software\\%' OR ParentImage ILIKE 'C:\\Program Files (x86)\\Avast Software\\%')) OR (ParentImage ILIKE 'C:\\ProgramData\\Avira\\%') OR ((ParentImage ILIKE 'C:\\Program Files\\Google\\Update\\%' OR ParentImage ILIKE 'C:\\Program Files (x86)\\Google\\Update\\%')) OR (ParentImage = 'C:\\Windows\\System32\\services.exe') OR ((CommandLine ILIKE '%\\system32\\msiexec.exe /V') OR (ParentCommandLine ILIKE '%\\system32\\msiexec.exe /V')) OR (ParentImage ILIKE 'C:\\ProgramData\\Sophos\\%'))))
