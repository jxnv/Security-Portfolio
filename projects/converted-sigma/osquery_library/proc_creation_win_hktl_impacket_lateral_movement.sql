-- Title: HackTool - Potential Impacket Lateral Movement Activity
-- ID: 10c14723-61c7-4c75-92ca-9af245723ad2
-- Status: stable
-- Level: high
-- Author: Ecco, oscd.community, Jonhnathan Ribeiro, Tim Rauch
-- Date: 2019-09-03
-- Tags: attack.execution, attack.t1047, attack.lateral-movement, attack.t1021.003
-- Description: Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentCommandLine LIKE '%svchost.exe -k netsvcs%' OR ParentCommandLine LIKE '%taskeng.exe%') AND (CommandLine LIKE '%cmd.exe%' AND CommandLine LIKE '%/C%' AND CommandLine LIKE '%Windows\\Temp\\%' AND CommandLine LIKE '%&1%')) OR ((ParentImage="*\\wmiprvse.exe" OR ParentImage="*\\mmc.exe" OR ParentImage="*\\explorer.exe" OR ParentImage="*\\services.exe") AND (CommandLine LIKE '%cmd.exe%' AND CommandLine LIKE '%/Q%' AND CommandLine LIKE '%/c%' AND CommandLine LIKE '%\\\\\\\\127.0.0.1\\\\%' AND CommandLine LIKE '%&1%')))
