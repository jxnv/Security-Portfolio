-- Title: Process Execution From Shared Memory Directory
-- ID: 5cd16c8f-44a6-4654-81e7-a84d6db507d4
-- Status: experimental
-- Level: high
-- Author: Stan Beukers
-- Date: 2026-06-20
-- Tags: attack.stealth, attack.execution, attack.t1027.011
-- Description: Detects the execution of a binary from the Linux shared memory directory /dev/shm.
-- This directory is a tmpfs mount backed entirely by RAM and is abused by attackers for fileless malware staging because files written there never touch physical disk and may evade disk-based detection.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '/dev/shm/%')
