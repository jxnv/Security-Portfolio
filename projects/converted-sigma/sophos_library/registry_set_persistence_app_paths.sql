-- Title: Potential Persistence Via App Paths Default Property
-- ID: 707e097c-e20f-4f67-8807-1f72ff4500d6
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-10
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.012
-- Description: Detects changes to the "Default" property for keys located in the \Software\Microsoft\Windows\CurrentVersion\App Paths\ registry. Which might be used as a method of persistence
-- The entries found under App Paths are used primarily for the following purposes.
-- First, to map an application's executable file name to that file's fully qualified path.
-- Second, to prepend information to the PATH environment variable on a per-application, per-process basis.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (TargetObject ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths%' AND (TargetObject ILIKE '%(Default)' OR TargetObject ILIKE '%Path') AND (Details ILIKE '%\\Users\\Public%' OR Details ILIKE '%\\AppData\\Local\\Temp\\%' OR Details ILIKE '%\\Windows\\Temp\\%' OR Details ILIKE '%\\Desktop\\%' OR Details ILIKE '%\\Downloads\\%' OR Details ILIKE '%%temp%%' OR Details ILIKE '%%tmp%%' OR Details ILIKE '%iex%' OR Details ILIKE '%Invoke-%' OR Details ILIKE '%rundll32%' OR Details ILIKE '%regsvr32%' OR Details ILIKE '%mshta%' OR Details ILIKE '%cscript%' OR Details ILIKE '%wscript%' OR Details ILIKE '%.bat%' OR Details ILIKE '%.hta%' OR Details ILIKE '%.dll%' OR Details ILIKE '%.ps1%'))
