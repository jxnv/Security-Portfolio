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

SELECT * FROM file WHERE (TargetObject LIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths%' AND (TargetObject="*(Default)" OR TargetObject="*Path") AND (Details LIKE '%\\Users\\Public%' OR Details LIKE '%\\AppData\\Local\\Temp\\%' OR Details LIKE '%\\Windows\\Temp\\%' OR Details LIKE '%\\Desktop\\%' OR Details LIKE '%\\Downloads\\%' OR Details LIKE '%%temp%%' OR Details LIKE '%%tmp%%' OR Details LIKE '%iex%' OR Details LIKE '%Invoke-%' OR Details LIKE '%rundll32%' OR Details LIKE '%regsvr32%' OR Details LIKE '%mshta%' OR Details LIKE '%cscript%' OR Details LIKE '%wscript%' OR Details LIKE '%.bat%' OR Details LIKE '%.hta%' OR Details LIKE '%.dll%' OR Details LIKE '%.ps1%'))
