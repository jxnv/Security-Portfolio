-- Title: System Network Connections Discovery - MacOs
-- ID: 9a7a0393-2144-4626-9bf1-7c2f5a7321db
-- Status: test
-- Level: informational
-- Author: Daniil Yugoslavskiy, oscd.community
-- Date: 2020-10-19
-- Tags: attack.discovery, attack.t1049
-- Description: Detects usage of system utilities to discover system network connections
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/who" OR Image="*/w" OR Image="*/last" OR Image="*/lsof" OR Image="*/netstat"))
