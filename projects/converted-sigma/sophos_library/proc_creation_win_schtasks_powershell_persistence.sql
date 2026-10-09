-- Title: Potential Persistence Via Powershell Search Order Hijacking - Task
-- ID: b66474aa-bd92-4333-a16c-298155b120df
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems), Florian Roth (Nextron Systems)
-- Date: 2022-04-08
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001
-- Description: Detects suspicious powershell execution via a schedule task where the command ends with an suspicious flags to hide the powershell instance instead of executeing scripts or commands. This could be a sign of persistence via PowerShell "Get-Variable" technique as seen being used in Colibri Loader
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ParentImage = 'C:\\WINDOWS\\System32\\svchost.exe' AND (ParentCommandLine ILIKE '%-k netsvcs%' AND ParentCommandLine ILIKE '%-s Schedule%') AND (CommandLine ILIKE '% -windowstyle hidden' OR CommandLine ILIKE '% -w hidden' OR CommandLine ILIKE '% -ep bypass' OR CommandLine ILIKE '% -noni'))
