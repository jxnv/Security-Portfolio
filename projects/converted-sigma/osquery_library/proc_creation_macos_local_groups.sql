-- Title: Local Groups Discovery - MacOs
-- ID: 89bb1f97-c7b9-40e8-b52b-7d6afbd67276
-- Status: test
-- Level: informational
-- Author: Ömer Günal, Alejandro Ortuno, oscd.community
-- Date: 2020-10-11
-- Tags: attack.discovery, attack.t1069.001
-- Description: Detects enumeration of local system groups
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*/dscacheutil" AND (CommandLine LIKE '%-q%' AND CommandLine LIKE '%group%')) OR (Image="*/cat" AND CommandLine LIKE '%/etc/group%') OR (Image="*/dscl" AND (CommandLine LIKE '%-list%' AND CommandLine LIKE '%/groups%')))
