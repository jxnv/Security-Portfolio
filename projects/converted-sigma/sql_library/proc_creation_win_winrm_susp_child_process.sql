-- Title: Suspicious Processes Spawned by WinRM
-- ID: 5cc2cda8-f261-4d88-a2de-e9e193c86716
-- Status: test
-- Level: high
-- Author: Andreas Hunkeler (@Karneades), Markus Neis
-- Date: 2021-05-20
-- Tags: attack.t1190, attack.initial-access, attack.persistence, attack.privilege-escalation
-- Description: Detects suspicious processes including shells spawnd from WinRM host process
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (ParentImage ILIKE '%\\wsmprovhost.exe' AND (Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\sh.exe' OR Image ILIKE '%\\bash.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\wsl.exe' OR Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\whoami.exe' OR Image ILIKE '%\\bitsadmin.exe'))
