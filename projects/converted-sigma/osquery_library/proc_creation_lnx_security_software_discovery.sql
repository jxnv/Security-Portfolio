-- Title: Security Software Discovery - Linux
-- ID: c9d8b7fd-78e4-44fe-88f6-599135d46d60
-- Status: test
-- Level: low
-- Author: Daniil Yugoslavskiy, oscd.community
-- Date: 2020-10-19
-- Tags: attack.discovery, attack.t1518.001
-- Description: Detects usage of system utilities (only grep and egrep for now) to discover security software discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/grep" OR Image="*/egrep") AND (CommandLine LIKE '%nessusd%' OR CommandLine LIKE '%td-agent%' OR CommandLine LIKE '%packetbeat%' OR CommandLine LIKE '%filebeat%' OR CommandLine LIKE '%auditbeat%' OR CommandLine LIKE '%osqueryd%' OR CommandLine LIKE '%cbagentd%' OR CommandLine LIKE '%falcond%'))
