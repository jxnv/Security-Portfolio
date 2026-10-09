-- Title: PUA - Advanced Port Scanner Execution
-- ID: 54773c5f-f1cc-4703-9126-2f797d96a69d
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-12-18
-- Tags: attack.discovery, attack.t1046, attack.t1135
-- Description: Detects the use of Advanced Port Scanner.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%/portable%' AND CommandLine LIKE '%/lng%')) OR ((Image LIKE '%\\advanced_port_scanner%') OR (OriginalFileName LIKE '%advanced_port_scanner%') OR (Description LIKE '%Advanced Port Scanner%')))
