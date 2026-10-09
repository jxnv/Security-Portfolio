// Title: DLL Load via LSASS
// ID: b3503044-60ce-4bf4-bbcb-e3db98788823
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-10-16
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1547.008
// Description: Detects a method to load DLL via LSASS process using an undocumented Registry key
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\CurrentControlSet\\Services\\NTDS\\DirectoryServiceExtPt" or TargetObject contains "\\CurrentControlSet\\Services\\NTDS\\LsaDbExtPt")) and not ((action_process_image_path = "C:\\Windows\\system32\\lsass.exe" and (Details = "%%systemroot%%\\system32\\ntdsa.dll" or Details = "%%systemroot%%\\system32\\lsadb.dll"))))
