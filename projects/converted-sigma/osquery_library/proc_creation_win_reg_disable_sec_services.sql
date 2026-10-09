-- Title: Security Service Disabled Via Reg.EXE
-- ID: 5e95028c-5229-4214-afae-d653d573d0ec
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), John Lambert (idea), elhoim
-- Date: 2021-07-14
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects execution of "reg.exe" to disable security services such as Windows Defender.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%d 4%' AND CommandLine LIKE '%v Start%') AND (CommandLine LIKE '%\\AppIDSvc%' OR CommandLine LIKE '%\\MsMpSvc%' OR CommandLine LIKE '%\\NisSrv%' OR CommandLine LIKE '%\\SecurityHealthService%' OR CommandLine LIKE '%\\Sense%' OR CommandLine LIKE '%\\UsoSvc%' OR CommandLine LIKE '%\\WdBoot%' OR CommandLine LIKE '%\\WdFilter%' OR CommandLine LIKE '%\\WdNisDrv%' OR CommandLine LIKE '%\\WdNisSvc%' OR CommandLine LIKE '%\\WinDefend%' OR CommandLine LIKE '%\\wscsvc%' OR CommandLine LIKE '%\\wuauserv%')) AND ((CommandLine LIKE '%reg%' AND CommandLine LIKE '%add%')))
