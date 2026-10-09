-- Title: DLL Load via LSASS
-- ID: b3503044-60ce-4bf4-bbcb-e3db98788823
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-10-16
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1547.008
-- Description: Detects a method to load DLL via LSASS process using an undocumented Registry key
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject LIKE '%\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt%' OR TargetObject LIKE '%\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt%')) AND NOT ((Image = 'C:\\Windows\\system32\\lsass.exe' AND (Details = '%%systemroot%%\\system32\\ntdsa.dll' OR Details = '%%systemroot%%\\system32\\lsadb.dll'))))
