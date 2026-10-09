-- Title: HackTool - SOAPHound Execution
-- ID: e92a4287-e072-4a40-9739-370c106bb750
-- Status: test
-- Level: high
-- Author: @kostastsale
-- Date: 2024-01-26
-- Tags: attack.discovery, attack.t1087
-- Description: Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% --buildcache %' OR CommandLine ILIKE '% --bhdump %' OR CommandLine ILIKE '% --certdump %' OR CommandLine ILIKE '% --dnsdump %')) AND ((CommandLine ILIKE '% -c %' OR CommandLine ILIKE '% --cachefilename %' OR CommandLine ILIKE '% -o %' OR CommandLine ILIKE '% --outputdirectory%')))
