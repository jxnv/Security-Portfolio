-- Title: Suspicious Processes Spawned by WinRM
-- ID: 5cc2cda8-f261-4d88-a2de-e9e193c86716
-- Status: test
-- Level: high
-- Author: Andreas Hunkeler (@Karneades), Markus Neis
-- Date: 2021-05-20
-- Tags: attack.t1190, attack.initial-access, attack.persistence, attack.privilege-escalation
-- Description: Detects suspicious processes including shells spawnd from WinRM host process
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (ParentImage="*\\wsmprovhost.exe" AND (Image="*\\cmd.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wsl.exe" OR Image="*\\schtasks.exe" OR Image="*\\certutil.exe" OR Image="*\\whoami.exe" OR Image="*\\bitsadmin.exe"))
