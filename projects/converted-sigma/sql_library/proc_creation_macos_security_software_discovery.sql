-- Title: Security Software Discovery - MacOs
-- ID: 0ed75b9c-c73b-424d-9e7d-496cd565fbe0
-- Status: test
-- Level: medium
-- Author: Daniil Yugoslavskiy, oscd.community
-- Date: 2020-10-19
-- Tags: attack.discovery, attack.t1518.001
-- Description: Detects usage of system utilities (only grep for now) to discover security software discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image = '/usr/bin/grep') AND (((CommandLine ILIKE '%nessusd%' OR CommandLine ILIKE '%santad%' OR CommandLine ILIKE '%CbDefense%' OR CommandLine ILIKE '%falcond%' OR CommandLine ILIKE '%td-agent%' OR CommandLine ILIKE '%packetbeat%' OR CommandLine ILIKE '%filebeat%' OR CommandLine ILIKE '%auditbeat%' OR CommandLine ILIKE '%osqueryd%' OR CommandLine ILIKE '%BlockBlock%' OR CommandLine ILIKE '%LuLu%')) OR ((CommandLine ILIKE '%Little%' AND CommandLine ILIKE '%Snitch%'))))
