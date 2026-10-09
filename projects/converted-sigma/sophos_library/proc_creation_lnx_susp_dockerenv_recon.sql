-- Title: Docker Container Discovery Via Dockerenv Listing
-- ID: 11701de9-d5a5-44aa-8238-84252f131895
-- Status: test
-- Level: low
-- Author: Seth Hanford
-- Date: 2023-08-23
-- Tags: attack.discovery, attack.t1082
-- Description: Detects listing or file reading of ".dockerenv" which can be a sing of potential container discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%/cat' OR Image ILIKE '%/dir' OR Image ILIKE '%/find' OR Image ILIKE '%/ls' OR Image ILIKE '%/stat' OR Image ILIKE '%/test' OR Image ILIKE '%grep') AND CommandLine ILIKE '%.dockerenv')
