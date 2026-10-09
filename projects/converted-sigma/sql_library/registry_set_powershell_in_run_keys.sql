-- Title: Suspicious PowerShell In Registry Run Keys
-- ID: 8d85cf08-bf97-4260-ba49-986a2a65129c
-- Status: test
-- Level: medium
-- Author: frack113, Florian Roth (Nextron Systems)
-- Date: 2022-03-17
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: Detects potential PowerShell commands or code within registry run keys
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR TargetObject ILIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR TargetObject ILIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%') AND (Details ILIKE '%powershell%' OR Details ILIKE '%pwsh %' OR Details ILIKE '%FromBase64String%' OR Details ILIKE '%.DownloadFile(%' OR Details ILIKE '%.DownloadString(%' OR Details ILIKE '% -w hidden %' OR Details ILIKE '% -w 1 %' OR Details ILIKE '%-windowstyle hidden%' OR Details ILIKE '%-window hidden%' OR Details ILIKE '% -nop %' OR Details ILIKE '% -encodedcommand %' OR Details ILIKE '%-ExecutionPolicy Bypass%' OR Details ILIKE '%Invoke-Expression%' OR Details ILIKE '%IEX (%' OR Details ILIKE '%Invoke-Command%' OR Details ILIKE '%ICM -%' OR Details ILIKE '%Invoke-WebRequest%' OR Details ILIKE '%IWR %' OR Details ILIKE '%Invoke-RestMethod%' OR Details ILIKE '%IRM %' OR Details ILIKE '% -noni %' OR Details ILIKE '% -noninteractive %'))
