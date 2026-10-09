-- Title: File Download Via Nscurl - MacOS
-- ID: 6d8a7cf1-8085-423b-b87d-7e880faabbdf
-- Status: test
-- Level: medium
-- Author: Daniel Cortez
-- Date: 2024-06-04
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects the execution of the nscurl utility in order to download files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%/nscurl' AND (CommandLine ILIKE '%--download %' OR CommandLine ILIKE '%--download-directory %' OR CommandLine ILIKE '%--output %' OR CommandLine ILIKE '%-dir %' OR CommandLine ILIKE '%-dl %' OR CommandLine ILIKE '%-ld%' OR CommandLine ILIKE '%-o %'))
