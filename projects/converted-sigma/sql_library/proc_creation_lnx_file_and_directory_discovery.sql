-- Title: File and Directory Discovery - Linux
-- ID: d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72
-- Status: test
-- Level: informational
-- Author: Daniil Yugoslavskiy, oscd.community, CheraghiMilad
-- Date: 2020-10-19
-- Tags: attack.discovery, attack.t1083
-- Description: Detects usage of system utilities such as "find", "tree", "findmnt", etc, to discover files, directories and network shares.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%/file' AND REGEXP_LIKE(CommandLine, '(.){200,}')) OR (Image ILIKE '%/find') OR (Image ILIKE '%/findmnt') OR (Image ILIKE '%/mlocate') OR (Image ILIKE '%/ls' AND CommandLine ILIKE '%-R%') OR (Image ILIKE '%/tree'))
