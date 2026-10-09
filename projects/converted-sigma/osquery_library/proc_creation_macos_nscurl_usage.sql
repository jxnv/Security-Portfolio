-- Title: File Download Via Nscurl - MacOS
-- ID: 6d8a7cf1-8085-423b-b87d-7e880faabbdf
-- Status: test
-- Level: medium
-- Author: Daniel Cortez
-- Date: 2024-06-04
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects the execution of the nscurl utility in order to download files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*/nscurl" AND (CommandLine LIKE '%--download %' OR CommandLine LIKE '%--download-directory %' OR CommandLine LIKE '%--output %' OR CommandLine LIKE '%-dir %' OR CommandLine LIKE '%-dl %' OR CommandLine LIKE '%-ld%' OR CommandLine LIKE '%-o %'))
