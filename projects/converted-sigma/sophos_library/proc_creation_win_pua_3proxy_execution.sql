-- Title: PUA - 3Proxy Execution
-- ID: f38a82d2-fba3-4781-b549-525efbec8506
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-09-13
-- Tags: attack.command-and-control, attack.t1572
-- Description: Detects the use of 3proxy, a tiny free proxy server
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\3proxy.exe') OR (CommandLine ILIKE '%.exe -i127.0.0.1 -p%') OR (Description = '3proxy - tiny proxy server'))
