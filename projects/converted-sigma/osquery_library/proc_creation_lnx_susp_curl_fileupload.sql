-- Title: Suspicious Curl File Upload - Linux
-- ID: 00b90cc1-17ec-402c-96ad-3a8117d7a582
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), Cedric MAURUGEON (Update)
-- Date: 2022-09-15
-- Tags: attack.exfiltration, attack.command-and-control, attack.t1567, attack.t1105
-- Description: Detects a suspicious curl process start the adds a file to a web request
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((((CommandLine LIKE '% --form%' OR CommandLine LIKE '% --upload-file %' OR CommandLine LIKE '% --data %' OR CommandLine LIKE '% --data-%')) OR (CommandLine=regex("\\s-[FTd]\\s"))) AND (Image="*/curl")) AND NOT (((CommandLine LIKE '%://localhost%' OR CommandLine LIKE '%://127.0.0.1%'))))
