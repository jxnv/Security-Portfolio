-- Title: Local Groups Discovery - MacOs
-- ID: 89bb1f97-c7b9-40e8-b52b-7d6afbd67276
-- Status: test
-- Level: informational
-- Author: Ömer Günal, Alejandro Ortuno, oscd.community
-- Date: 2020-10-11
-- Tags: attack.discovery, attack.t1069.001
-- Description: Detects enumeration of local system groups
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%/dscacheutil' AND (CommandLine ILIKE '%-q%' AND CommandLine ILIKE '%group%')) OR (Image ILIKE '%/cat' AND CommandLine ILIKE '%/etc/group%') OR (Image ILIKE '%/dscl' AND (CommandLine ILIKE '%-list%' AND CommandLine ILIKE '%/groups%')))
