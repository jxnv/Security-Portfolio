-- Title: Suspicious Shell Open Command Registry Modification
-- ID: 9e8894c0-0ae0-11ef-9d85-1f2942bec57c
-- Status: experimental
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-01-24
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1548.002, attack.t1546.001
-- Description: Detects modifications to shell open registry keys that point to suspicious locations typically used by malware for persistence.
-- Generally, modifications to the `*\shell\open\command` registry key can indicate an attempt to change the default action for opening files,
-- and various UAC bypass or persistence techniques involve modifying these keys to execute malicious scripts or binaries.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (TargetObject LIKE '%\\shell\\open\\command\\%' AND (Details LIKE '%\\$Recycle.Bin\\%' OR Details LIKE '%\\AppData\\Local\\Temp\\%' OR Details LIKE '%\\Contacts\\%' OR Details LIKE '%\\Music\\%' OR Details LIKE '%\\PerfLogs\\%' OR Details LIKE '%\\Photos\\%' OR Details LIKE '%\\Pictures\\%' OR Details LIKE '%\\Users\\Public\\%' OR Details LIKE '%\\Videos\\%' OR Details LIKE '%\\Windows\\Temp\\%' OR Details LIKE '%%AppData%%' OR Details LIKE '%%LocalAppData%%' OR Details LIKE '%%Temp%%' OR Details LIKE '%%tmp%%'))
