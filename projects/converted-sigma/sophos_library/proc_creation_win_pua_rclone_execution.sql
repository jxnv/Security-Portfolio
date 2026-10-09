-- Title: PUA - Rclone Execution
-- ID: e37db05d-d1f9-49c8-b464-cee1a4b11638
-- Status: test
-- Level: high
-- Author: Bhabesh Raj, Sittikorn S, Aaron Greetham (@beardofbinary) - NCC Group
-- Date: 2021-05-10
-- Tags: attack.exfiltration, attack.t1567.002
-- Description: Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%--config %' AND CommandLine ILIKE '%--no-check-certificate %' AND CommandLine ILIKE '% copy %')) OR (((CommandLine ILIKE '%pass%' OR CommandLine ILIKE '%user%' OR CommandLine ILIKE '%copy%' OR CommandLine ILIKE '%sync%' OR CommandLine ILIKE '%config%' OR CommandLine ILIKE '%lsd%' OR CommandLine ILIKE '%remote%' OR CommandLine ILIKE '%ls%' OR CommandLine ILIKE '%mega%' OR CommandLine ILIKE '%pcloud%' OR CommandLine ILIKE '%ftp%' OR CommandLine ILIKE '%ignore-existing%' OR CommandLine ILIKE '%auto-confirm%' OR CommandLine ILIKE '%transfers%' OR CommandLine ILIKE '%multi-thread-streams%' OR CommandLine ILIKE '%no-check-certificate %')) AND ((Image ILIKE '%\\rclone.exe') OR (Description = 'Rsync for cloud storage'))))
