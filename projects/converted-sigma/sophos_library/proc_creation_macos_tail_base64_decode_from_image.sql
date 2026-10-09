-- Title: Potential Base64 Decoded From Images
-- ID: 09a910bf-f71f-4737-9c40-88880ba5913d
-- Status: test
-- Level: high
-- Author: Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date: 2023-12-20
-- Tags: attack.stealth, attack.t1140
-- Description: Detects the use of tail to extract bytes at an offset from an image and then decode the base64 value to create a new file with the decoded content. The detected execution is a bash one-liner.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%base64%' AND CommandLine ILIKE '%-d%' AND CommandLine ILIKE '%>%')) AND ((CommandLine ILIKE '%.avif%' OR CommandLine ILIKE '%.gif%' OR CommandLine ILIKE '%.jfif%' OR CommandLine ILIKE '%.jpeg%' OR CommandLine ILIKE '%.jpg%' OR CommandLine ILIKE '%.pjp%' OR CommandLine ILIKE '%.pjpeg%' OR CommandLine ILIKE '%.png%' OR CommandLine ILIKE '%.svg%' OR CommandLine ILIKE '%.webp%')) AND (Image ILIKE '%/bash') AND ((CommandLine ILIKE '%tail%' AND CommandLine ILIKE '%-c%')))
