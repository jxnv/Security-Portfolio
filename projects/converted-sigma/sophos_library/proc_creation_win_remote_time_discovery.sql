-- Title: Discovery of a System Time
-- ID: b243b280-65fe-48df-ba07-6ddea7646427
-- Status: test
-- Level: low
-- Author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
-- Date: 2019-10-24
-- Tags: attack.discovery, attack.t1124
-- Description: Identifies use of various commands to query a systems time. This technique may be used before executing a scheduled task or to discover the time zone of a target system.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe') AND CommandLine ILIKE '%time%') OR (Image ILIKE '%\\w32tm.exe' AND CommandLine ILIKE '%tz%'))
