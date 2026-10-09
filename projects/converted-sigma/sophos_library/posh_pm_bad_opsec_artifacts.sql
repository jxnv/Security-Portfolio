-- Title: Bad Opsec Powershell Code Artifacts
-- ID: 8d31a8ce-46b5-4dd6-bdc3-680931f1db86
-- Status: test
-- Level: critical
-- Author: ok @securonix invrep_de, oscd.community
-- Date: 2020-10-09
-- Tags: attack.execution, attack.t1059.001
-- Description: focuses on trivial artifacts observed in variants of prevalent offensive ps1 payloads, including
-- Cobalt Strike Beacon, PoshC2, Powerview, Letmein, Empire, Powersploit, and other attack payloads
-- that often undergo minimal changes by attackers due to bad opsec.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Payload ILIKE '%$DoIt%' OR Payload ILIKE '%harmj0y%' OR Payload ILIKE '%mattifestation%' OR Payload ILIKE '%_RastaMouse%' OR Payload ILIKE '%tifkin_%' OR Payload ILIKE '%0xdeadbeef%'))
