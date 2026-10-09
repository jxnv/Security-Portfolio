-- Title: PUA - Advanced Port Scanner Execution
-- ID: 54773c5f-f1cc-4703-9126-2f797d96a69d
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-12-18
-- Tags: attack.discovery, attack.t1046, attack.t1135
-- Description: Detects the use of Advanced Port Scanner.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%/portable%' AND CommandLine ILIKE '%/lng%')) OR ((Image ILIKE '%\\advanced_port_scanner%') OR (OriginalFileName ILIKE '%advanced_port_scanner%') OR (Description ILIKE '%Advanced Port Scanner%')))
