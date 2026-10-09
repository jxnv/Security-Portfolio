-- Title: MacOS Network Service Scanning
-- ID: 84bae5d4-b518-4ae0-b331-6d4afd34d00f
-- Status: test
-- Level: low
-- Author: Alejandro Ortuno, oscd.community
-- Date: 2020-10-21
-- Tags: attack.discovery, attack.t1046
-- Description: Detects enumeration of local or remote network services.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((Image ILIKE '%/nc' OR Image ILIKE '%/netcat')) AND NOT ((CommandLine ILIKE '%l%'))) OR ((Image ILIKE '%/nmap' OR Image ILIKE '%/telnet')))
