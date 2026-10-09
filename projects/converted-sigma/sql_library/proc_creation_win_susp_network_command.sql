-- Title: Suspicious Network Command
-- ID: a29c1813-ab1f-4dde-b489-330b952e91ae
-- Status: test
-- Level: low
-- Author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
-- Date: 2021-12-07
-- Tags: attack.discovery, attack.t1016
-- Description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((REGEXP_LIKE(CommandLine, 'ipconfig\s+/all') OR REGEXP_LIKE(CommandLine, 'netsh\s+interface show interface') OR REGEXP_LIKE(CommandLine, 'arp\s+-a') OR REGEXP_LIKE(CommandLine, 'nbtstat\s+-n') OR REGEXP_LIKE(CommandLine, 'net\s+config') OR REGEXP_LIKE(CommandLine, 'route\s+print')))
