-- Title: System Network Connections Discovery - Linux
-- ID: 4c519226-f0cd-4471-bd2f-6fbb2bb68a79
-- Status: test
-- Level: low
-- Author: Daniil Yugoslavskiy, oscd.community
-- Date: 2020-10-19
-- Tags: attack.discovery, attack.t1049
-- Description: Detects usage of system utilities to discover system network connections
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*/who" OR Image="*/w" OR Image="*/last" OR Image="*/lsof" OR Image="*/netstat")) AND NOT ((ParentCommandLine LIKE '%/usr/bin/landscape-sysinfo%' AND Image="*/who")))
