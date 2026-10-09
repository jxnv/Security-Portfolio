-- Title: Potential Base64 Decoded From Images
-- ID: 09a910bf-f71f-4737-9c40-88880ba5913d
-- Status: test
-- Level: high
-- Author: Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date: 2023-12-20
-- Tags: attack.stealth, attack.t1140
-- Description: Detects the use of tail to extract bytes at an offset from an image and then decode the base64 value to create a new file with the decoded content. The detected execution is a bash one-liner.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%base64%' AND CommandLine LIKE '%-d%' AND CommandLine LIKE '%>%')) AND ((CommandLine LIKE '%.avif%' OR CommandLine LIKE '%.gif%' OR CommandLine LIKE '%.jfif%' OR CommandLine LIKE '%.jpeg%' OR CommandLine LIKE '%.jpg%' OR CommandLine LIKE '%.pjp%' OR CommandLine LIKE '%.pjpeg%' OR CommandLine LIKE '%.png%' OR CommandLine LIKE '%.svg%' OR CommandLine LIKE '%.webp%')) AND (Image="*/bash") AND ((CommandLine LIKE '%tail%' AND CommandLine LIKE '%-c%')))
