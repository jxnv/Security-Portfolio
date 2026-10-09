-- Title: Firewall Configuration Discovery Via Netsh.EXE
-- ID: 0e4164da-94bc-450d-a7be-a4b176179f1f
-- Status: test
-- Level: low
-- Author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
-- Date: 2021-12-07
-- Tags: attack.discovery, attack.t1016
-- Description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%netsh%' AND CommandLine LIKE '%show %' AND CommandLine LIKE '%firewall %') AND (CommandLine LIKE '%config %' OR CommandLine LIKE '%state %' OR CommandLine LIKE '%rule %' OR CommandLine LIKE '%name=all%')) AND ((Image="*\\netsh.exe") OR (OriginalFileName = 'netsh.exe')))
