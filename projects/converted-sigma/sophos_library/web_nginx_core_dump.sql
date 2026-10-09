-- Title: Nginx Core Dump
-- ID: 59ec40bb-322e-40ab-808d-84fa690d7e56
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-05-31
-- Tags: attack.impact, attack.t1499.004
-- Description: Detects a core dump of a crashing Nginx worker process, which could be a signal of a serious problem or exploitation attempts.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ("exited on signal 6 (core dumped)")
