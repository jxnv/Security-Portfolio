-- Title: PUA - Chisel Tunneling Tool Execution
-- ID: 8b0e12da-d3c3-49db-bb4f-256703f380e5
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-09-13
-- Tags: attack.command-and-control, attack.t1090.001
-- Description: Detects usage of the Chisel tunneling tool via the commandline arguments
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\chisel.exe") OR (((CommandLine LIKE '%exe client %' OR CommandLine LIKE '%exe server %')) AND ((CommandLine LIKE '%-socks5%' OR CommandLine LIKE '%-reverse%' OR CommandLine LIKE '% r:%' OR CommandLine LIKE '%:127.0.0.1:%' OR CommandLine LIKE '%-tls-skip-verify %' OR CommandLine LIKE '%:socks%'))))
