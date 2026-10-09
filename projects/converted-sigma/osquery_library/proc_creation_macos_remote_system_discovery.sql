-- Title: Macos Remote System Discovery
-- ID: 10227522-8429-47e6-a301-f2b2d014e7ad
-- Status: test
-- Level: informational
-- Author: Alejandro Ortuno, oscd.community
-- Date: 2020-10-22
-- Tags: attack.discovery, attack.t1018
-- Description: Detects the enumeration of other remote systems.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/arp" AND CommandLine LIKE '%-a%') OR (Image="*/ping" AND (CommandLine LIKE '% 10.%' OR CommandLine LIKE '% 192.168.%' OR CommandLine LIKE '% 172.16.%' OR CommandLine LIKE '% 172.17.%' OR CommandLine LIKE '% 172.18.%' OR CommandLine LIKE '% 172.19.%' OR CommandLine LIKE '% 172.20.%' OR CommandLine LIKE '% 172.21.%' OR CommandLine LIKE '% 172.22.%' OR CommandLine LIKE '% 172.23.%' OR CommandLine LIKE '% 172.24.%' OR CommandLine LIKE '% 172.25.%' OR CommandLine LIKE '% 172.26.%' OR CommandLine LIKE '% 172.27.%' OR CommandLine LIKE '% 172.28.%' OR CommandLine LIKE '% 172.29.%' OR CommandLine LIKE '% 172.30.%' OR CommandLine LIKE '% 172.31.%' OR CommandLine LIKE '% 127.%' OR CommandLine LIKE '% 169.254.%')))
