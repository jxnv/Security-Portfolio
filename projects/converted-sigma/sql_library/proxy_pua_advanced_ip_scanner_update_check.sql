-- Title: PUA - Advanced IP/Port Scanner Update Check
-- ID: 1a9bb21a-1bb5-42d7-aa05-3219c7c8f47d
-- Status: test
-- Level: medium
-- Author: Axel Olsson
-- Date: 2022-08-14
-- Tags: attack.discovery, attack.reconnaissance, attack.t1590
-- Description: Detect the update check performed by Advanced IP/Port Scanner utilities.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (c-uri ILIKE '%/checkupdate.php%' AND (c-uri-query ILIKE '%lng=%' AND c-uri-query ILIKE '%ver=%' AND c-uri-query ILIKE '%beta=%' AND c-uri-query ILIKE '%type=%' AND c-uri-query ILIKE '%rmode=%' AND c-uri-query ILIKE '%product=%'))
