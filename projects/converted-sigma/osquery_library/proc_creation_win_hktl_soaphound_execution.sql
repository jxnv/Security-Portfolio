-- Title: HackTool - SOAPHound Execution
-- ID: e92a4287-e072-4a40-9739-370c106bb750
-- Status: test
-- Level: high
-- Author: @kostastsale
-- Date: 2024-01-26
-- Tags: attack.discovery, attack.t1087
-- Description: Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% --buildcache %' OR CommandLine LIKE '% --bhdump %' OR CommandLine LIKE '% --certdump %' OR CommandLine LIKE '% --dnsdump %')) AND ((CommandLine LIKE '% -c %' OR CommandLine LIKE '% --cachefilename %' OR CommandLine LIKE '% -o %' OR CommandLine LIKE '% --outputdirectory%')))
