-- Title: UAC Bypass Using NTFS Reparse Point - Process
-- ID: 39ed3c80-e6a1-431b-9df3-911ac53d08a7
-- Status: test
-- Level: high
-- Author: Christian Burkard (Nextron Systems)
-- Date: 2021-08-30
-- Tags: attack.privilege-escalation, attack.t1548.002
-- Description: Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '\"C:\\Windows\\system32\\wusa.exe\"  /quiet C:\\Users\\%' AND CommandLine ILIKE '%\\AppData\\Local\\Temp\\update.msu' AND (IntegrityLevel = 'High' OR IntegrityLevel = 'System' OR IntegrityLevel = 'S-1-16-16384' OR IntegrityLevel = 'S-1-16-12288')) OR (ParentCommandLine = '\"C:\\Windows\\system32\\dism.exe\" /online /quiet /norestart /add-package /packagepath:\"C:\\Windows\\system32\\pe386\" /ignorecheck' AND (IntegrityLevel = 'High' OR IntegrityLevel = 'System') AND (CommandLine ILIKE '%C:\\Users\\%' AND CommandLine ILIKE '%\\AppData\\Local\\Temp\\%' AND CommandLine ILIKE '%\\dismhost.exe {%') AND Image ILIKE '%\\DismHost.exe'))
