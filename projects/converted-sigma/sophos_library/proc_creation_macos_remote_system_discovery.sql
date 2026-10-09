-- Title: Macos Remote System Discovery
-- ID: 10227522-8429-47e6-a301-f2b2d014e7ad
-- Status: test
-- Level: informational
-- Author: Alejandro Ortuno, oscd.community
-- Date: 2020-10-22
-- Tags: attack.discovery, attack.t1018
-- Description: Detects the enumeration of other remote systems.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%/arp' AND CommandLine ILIKE '%-a%') OR (Image ILIKE '%/ping' AND (CommandLine ILIKE '% 10.%' OR CommandLine ILIKE '% 192.168.%' OR CommandLine ILIKE '% 172.16.%' OR CommandLine ILIKE '% 172.17.%' OR CommandLine ILIKE '% 172.18.%' OR CommandLine ILIKE '% 172.19.%' OR CommandLine ILIKE '% 172.20.%' OR CommandLine ILIKE '% 172.21.%' OR CommandLine ILIKE '% 172.22.%' OR CommandLine ILIKE '% 172.23.%' OR CommandLine ILIKE '% 172.24.%' OR CommandLine ILIKE '% 172.25.%' OR CommandLine ILIKE '% 172.26.%' OR CommandLine ILIKE '% 172.27.%' OR CommandLine ILIKE '% 172.28.%' OR CommandLine ILIKE '% 172.29.%' OR CommandLine ILIKE '% 172.30.%' OR CommandLine ILIKE '% 172.31.%' OR CommandLine ILIKE '% 127.%' OR CommandLine ILIKE '% 169.254.%')))
