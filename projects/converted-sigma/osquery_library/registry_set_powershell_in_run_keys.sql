-- Title: Suspicious PowerShell In Registry Run Keys
-- ID: 8d85cf08-bf97-4260-ba49-986a2a65129c
-- Status: test
-- Level: medium
-- Author: frack113, Florian Roth (Nextron Systems)
-- Date: 2022-03-17
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects potential PowerShell commands or code within registry run keys
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR TargetObject LIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR TargetObject LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%') AND (Details LIKE '%powershell%' OR Details LIKE '%pwsh %' OR Details LIKE '%FromBase64String%' OR Details LIKE '%.DownloadFile(%' OR Details LIKE '%.DownloadString(%' OR Details LIKE '% -w hidden %' OR Details LIKE '% -w 1 %' OR Details LIKE '%-windowstyle hidden%' OR Details LIKE '%-window hidden%' OR Details LIKE '% -nop %' OR Details LIKE '% -encodedcommand %' OR Details LIKE '%-ExecutionPolicy Bypass%' OR Details LIKE '%Invoke-Expression%' OR Details LIKE '%IEX (%' OR Details LIKE '%Invoke-Command%' OR Details LIKE '%ICM -%' OR Details LIKE '%Invoke-WebRequest%' OR Details LIKE '%IWR %' OR Details LIKE '%Invoke-RestMethod%' OR Details LIKE '%IRM %' OR Details LIKE '% -noni %' OR Details LIKE '% -noninteractive %'))
