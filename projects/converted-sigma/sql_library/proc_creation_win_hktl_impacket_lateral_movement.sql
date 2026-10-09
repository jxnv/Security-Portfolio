-- Title: HackTool - Potential Impacket Lateral Movement Activity
-- ID: 10c14723-61c7-4c75-92ca-9af245723ad2
-- Status: stable
-- Level: high
-- Author: Ecco, oscd.community, Jonhnathan Ribeiro, Tim Rauch
-- Date: 2019-09-03
-- Tags: attack.execution, attack.t1047, attack.lateral-movement, attack.t1021.003
-- Description: Detects wmiexec/dcomexec/atexec/smbexec from Impacket framework
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ParentCommandLine ILIKE '%svchost.exe -k netsvcs%' OR ParentCommandLine ILIKE '%taskeng.exe%') AND (CommandLine ILIKE '%cmd.exe%' AND CommandLine ILIKE '%/C%' AND CommandLine ILIKE '%Windows\\Temp\\%' AND CommandLine ILIKE '%&1%')) OR ((ParentImage ILIKE '%\\wmiprvse.exe' OR ParentImage ILIKE '%\\mmc.exe' OR ParentImage ILIKE '%\\explorer.exe' OR ParentImage ILIKE '%\\services.exe') AND (CommandLine ILIKE '%cmd.exe%' AND CommandLine ILIKE '%/Q%' AND CommandLine ILIKE '%/c%' AND CommandLine ILIKE '%\\\\\\\\127.0.0.1\\\\%' AND CommandLine ILIKE '%&1%')))
