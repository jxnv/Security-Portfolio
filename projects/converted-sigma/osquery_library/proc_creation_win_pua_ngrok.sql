-- Title: PUA - Ngrok Execution
-- ID: ee37eb7c-a4e7-4cd5-8fa4-efa27f1c3f31
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-05-14
-- Tags: attack.command-and-control, attack.t1572
-- Description: Detects the use of Ngrok, a utility used for port forwarding and tunneling, often used by threat actors to make local protected services publicly available.
-- Involved domains are bin.equinox.io for download and *.ngrok.io for connections.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% tcp 139%' OR CommandLine LIKE '% tcp 445%' OR CommandLine LIKE '% tcp 3389%' OR CommandLine LIKE '% tcp 5985%' OR CommandLine LIKE '% tcp 5986%')) OR ((CommandLine LIKE '% start %' AND CommandLine LIKE '%--all%' AND CommandLine LIKE '%--config%' AND CommandLine LIKE '%.yml%')) OR (Image="*ngrok.exe" AND (CommandLine LIKE '% tcp %' OR CommandLine LIKE '% http %' OR CommandLine LIKE '% authtoken %')) OR ((CommandLine LIKE '%.exe authtoken %' OR CommandLine LIKE '%.exe start --all%')))
