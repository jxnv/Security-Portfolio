-- Title: Disable Windows Event Logging Via Registry
-- ID: 2f78da12-f7c7-430b-8b19-a28f269b77a3
-- Status: test
-- Level: high
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-04
-- Tags: attack.defense-impairment, attack.t1685.001
-- Description: Detects tampering with the "Enabled" registry key in order to disable Windows logging of a Windows event channel
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\%' AND TargetObject="*\\Enabled" AND Details = 'DWORD (0x00000000)') AND NOT (((Image="C:\\Windows\\winsxs\\*" AND Image="*\\TiWorker.exe") OR (Image = 'C:\\Windows\\System32\\svchost.exe' AND (TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-FileInfoMinifilter%' OR TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-ASN1\\%' OR TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Kernel-AppCompat\\%' OR TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Runtime\\Error\\%' OR TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-CAPI2/Operational\\%')) OR (Image = 'C:\\Windows\\servicing\\TrustedInstaller.exe' AND TargetObject LIKE '%\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Compat-Appraiser%') OR (Image = 'C:\\Windows\\system32\\wevtutil.exe'))) AND NOT (((Image = '') OR (NOT Image=*))))
