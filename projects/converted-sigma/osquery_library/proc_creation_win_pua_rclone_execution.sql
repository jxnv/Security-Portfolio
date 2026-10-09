-- Title: PUA - Rclone Execution
-- ID: e37db05d-d1f9-49c8-b464-cee1a4b11638
-- Status: test
-- Level: high
-- Author: Bhabesh Raj, Sittikorn S, Aaron Greetham (@beardofbinary) - NCC Group
-- Date: 2021-05-10
-- Tags: attack.exfiltration, attack.t1567.002
-- Description: Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%--config %' AND CommandLine LIKE '%--no-check-certificate %' AND CommandLine LIKE '% copy %')) OR (((CommandLine LIKE '%pass%' OR CommandLine LIKE '%user%' OR CommandLine LIKE '%copy%' OR CommandLine LIKE '%sync%' OR CommandLine LIKE '%config%' OR CommandLine LIKE '%lsd%' OR CommandLine LIKE '%remote%' OR CommandLine LIKE '%ls%' OR CommandLine LIKE '%mega%' OR CommandLine LIKE '%pcloud%' OR CommandLine LIKE '%ftp%' OR CommandLine LIKE '%ignore-existing%' OR CommandLine LIKE '%auto-confirm%' OR CommandLine LIKE '%transfers%' OR CommandLine LIKE '%multi-thread-streams%' OR CommandLine LIKE '%no-check-certificate %')) AND ((Image="*\\rclone.exe") OR (Description = 'Rsync for cloud storage'))))
