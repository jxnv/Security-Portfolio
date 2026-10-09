-- Title: Security Software Discovery - MacOs
-- ID: 0ed75b9c-c73b-424d-9e7d-496cd565fbe0
-- Status: test
-- Level: medium
-- Author: Daniil Yugoslavskiy, oscd.community
-- Date: 2020-10-19
-- Tags: attack.discovery, attack.t1518.001
-- Description: Detects usage of system utilities (only grep for now) to discover security software discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image = '/usr/bin/grep') AND (((CommandLine LIKE '%nessusd%' OR CommandLine LIKE '%santad%' OR CommandLine LIKE '%CbDefense%' OR CommandLine LIKE '%falcond%' OR CommandLine LIKE '%td-agent%' OR CommandLine LIKE '%packetbeat%' OR CommandLine LIKE '%filebeat%' OR CommandLine LIKE '%auditbeat%' OR CommandLine LIKE '%osqueryd%' OR CommandLine LIKE '%BlockBlock%' OR CommandLine LIKE '%LuLu%')) OR ((CommandLine LIKE '%Little%' AND CommandLine LIKE '%Snitch%'))))
