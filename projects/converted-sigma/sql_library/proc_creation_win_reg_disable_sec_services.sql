-- Title: Security Service Disabled Via Reg.EXE
-- ID: 5e95028c-5229-4214-afae-d653d573d0ec
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), John Lambert (idea), elhoim
-- Date: 2021-07-14
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects execution of "reg.exe" to disable security services such as Windows Defender.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%d 4%' AND CommandLine ILIKE '%v Start%') AND (CommandLine ILIKE '%\\AppIDSvc%' OR CommandLine ILIKE '%\\MsMpSvc%' OR CommandLine ILIKE '%\\NisSrv%' OR CommandLine ILIKE '%\\SecurityHealthService%' OR CommandLine ILIKE '%\\Sense%' OR CommandLine ILIKE '%\\UsoSvc%' OR CommandLine ILIKE '%\\WdBoot%' OR CommandLine ILIKE '%\\WdFilter%' OR CommandLine ILIKE '%\\WdNisDrv%' OR CommandLine ILIKE '%\\WdNisSvc%' OR CommandLine ILIKE '%\\WinDefend%' OR CommandLine ILIKE '%\\wscsvc%' OR CommandLine ILIKE '%\\wuauserv%')) AND ((CommandLine ILIKE '%reg%' AND CommandLine ILIKE '%add%')))
