-- Title: WMIC Remote Command Execution
-- ID: 7773b877-5abb-4a3e-b9c9-fd0369b59b00
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-14
-- Tags: attack.execution, attack.t1047
-- Description: Detects the execution of WMIC to query information on a remote system
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%/node:%' OR CommandLine ILIKE '%-node:%')) AND ((Image ILIKE '%\\WMIC.exe') OR (OriginalFileName = 'wmic.exe'))) AND NOT (((CommandLine ILIKE '%localhost%' OR CommandLine ILIKE '%127.0.0.1%'))))
