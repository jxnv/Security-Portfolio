-- Title: Security Software Discovery - Linux
-- ID: c9d8b7fd-78e4-44fe-88f6-599135d46d60
-- Status: test
-- Level: low
-- Author: Daniil Yugoslavskiy, oscd.community
-- Date: 2020-10-19
-- Tags: attack.discovery, attack.t1518.001
-- Description: Detects usage of system utilities (only grep and egrep for now) to discover security software discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%/grep' OR Image ILIKE '%/egrep') AND (CommandLine ILIKE '%nessusd%' OR CommandLine ILIKE '%td-agent%' OR CommandLine ILIKE '%packetbeat%' OR CommandLine ILIKE '%filebeat%' OR CommandLine ILIKE '%auditbeat%' OR CommandLine ILIKE '%osqueryd%' OR CommandLine ILIKE '%cbagentd%' OR CommandLine ILIKE '%falcond%'))
