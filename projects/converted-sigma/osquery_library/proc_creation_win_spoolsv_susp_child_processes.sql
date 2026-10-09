-- Title: Suspicious Spool Service Child Process
-- ID: dcdbc940-0bff-46b2-95f3-2d73f848e33b
-- Status: test
-- Level: high
-- Author: Justin C. (@endisphotic), @dreadphones (detection), Thomas Patzke (Sigma rule)
-- Date: 2021-07-11
-- Tags: attack.execution, attack.t1203, attack.privilege-escalation, attack.t1068
-- Description: Detects suspicious print spool service (spoolsv.exe) child processes.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\spoolsv.exe" AND (IntegrityLevel = 'System' OR IntegrityLevel = 'S-1-16-16384')) AND (((Image="*\\gpupdate.exe" OR Image="*\\whoami.exe" OR Image="*\\nltest.exe" OR Image="*\\taskkill.exe" OR Image="*\\wmic.exe" OR Image="*\\taskmgr.exe" OR Image="*\\sc.exe" OR Image="*\\findstr.exe" OR Image="*\\curl.exe" OR Image="*\\wget.exe" OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\accesschk.exe" OR Image="*\\wevtutil.exe" OR Image="*\\bcdedit.exe" OR Image="*\\fsutil.exe" OR Image="*\\cipher.exe" OR Image="*\\schtasks.exe" OR Image="*\\write.exe" OR Image="*\\wuauclt.exe" OR Image="*\\systeminfo.exe" OR Image="*\\reg.exe" OR Image="*\\query.exe")) OR (((Image="*\\net.exe" OR Image="*\\net1.exe")) AND NOT ((CommandLine LIKE '%start%'))) OR ((Image="*\\cmd.exe") AND NOT (((CommandLine LIKE '%.spl%' OR CommandLine LIKE '%route add%' OR CommandLine LIKE '%program files%')))) OR ((Image="*\\netsh.exe") AND NOT (((CommandLine LIKE '%add portopening%' OR CommandLine LIKE '%rule name%')))) OR (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) AND NOT ((CommandLine LIKE '%.spl%'))) OR ((CommandLine="*rundll32.exe") AND ((Image="*\\rundll32.exe") OR (OriginalFileName = 'RUNDLL32.EXE')))))
