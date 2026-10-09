-- Title: WhoAmI as Parameter
-- ID: e9142d84-fbe0-401d-ac50-3e519fb00c89
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-11-29
-- Tags: attack.discovery, attack.t1033, car.2016-03-001
-- Description: Detects a suspicious process command line that uses whoami as first parameter (as e.g. used by EfsPotato)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (CommandLine ILIKE '%.exe whoami%')
