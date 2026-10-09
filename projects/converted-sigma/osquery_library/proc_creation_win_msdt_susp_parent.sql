-- Title: Suspicious MSDT Parent Process
-- ID: 7a74da6b-ea76-47db-92cc-874ad90df734
-- Status: test
-- Level: high
-- Author: Nextron Systems
-- Date: 2022-06-01
-- Tags: attack.stealth, attack.t1036, attack.t1218
-- Description: Detects msdt.exe executed by a suspicious parent as seen in CVE-2022-30190 / Follina exploitation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\msdt.exe") OR (OriginalFileName = 'msdt.exe')) AND ((ParentImage="*\\cmd.exe" OR ParentImage="*\\cscript.exe" OR ParentImage="*\\mshta.exe" OR ParentImage="*\\powershell.exe" OR ParentImage="*\\pwsh.exe" OR ParentImage="*\\regsvr32.exe" OR ParentImage="*\\rundll32.exe" OR ParentImage="*\\schtasks.exe" OR ParentImage="*\\wmic.exe" OR ParentImage="*\\wscript.exe" OR ParentImage="*\\wsl.exe")))
