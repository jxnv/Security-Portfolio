-- Title: HackTool - Hashcat Password Cracker Execution
-- ID: 39b31e81-5f5f-4898-9c0e-2160cfc0f9bf
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2021-12-27
-- Tags: attack.credential-access, attack.t1110.002
-- Description: Execute Hashcat.exe with provided SAM file from registry of Windows and Password list to crack against
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%-a %' AND CommandLine ILIKE '%-m 1000 %' AND CommandLine ILIKE '%-r %')) OR (Image ILIKE '%\\hashcat.exe'))
