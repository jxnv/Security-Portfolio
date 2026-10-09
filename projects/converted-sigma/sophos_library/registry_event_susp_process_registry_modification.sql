-- Title: Registry Tampering by Potentially Suspicious Processes
-- ID: 7f4c43f9-b1a5-4c7d-b24a-b41bf3a3ebf2
-- Status: experimental
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-08-13
-- Tags: attack.persistence, attack.execution, attack.defense-impairment, attack.t1112, attack.t1059.005
-- Description: Detects suspicious registry modifications made by suspicious processes such as script engine processes such as WScript, or CScript etc.
-- These processes are rarely used for legitimate registry modifications, and their activity may indicate an attempt to modify the registry
-- without using standard tools like regedit.exe or reg.exe, potentially for evasion and persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\cscript.exe')) AND NOT (((Details = 'Binary Data') OR (Details IS NULL) OR (Image ILIKE '%\\wscript.exe' AND (TargetObject ILIKE '%SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications\\Data\\%' OR TargetObject ILIKE '%\\Services\\bam\\State\\UserSettings\\S-1-%' OR TargetObject ILIKE '%Software\\Microsoft\\Windows Script\\Settings\\Telemetry\\wscript.exe\\%' OR TargetObject ILIKE '%Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\%')) OR (Image ILIKE '%\\wscript.exe' AND TargetObject ILIKE '%\\wscript.exe%'))))
