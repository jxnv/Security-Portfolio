-- Title: System Integrity Protection (SIP) Disabled
-- ID: 3603f18a-ec15-43a1-9af2-d196c8a7fec6
-- Status: test
-- Level: medium
-- Author: Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date: 2024-01-02
-- Tags: attack.discovery, attack.t1518.001
-- Description: Detects the use of csrutil to disable the Configure System Integrity Protection (SIP). This technique is used in post-exploit scenarios.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%/csrutil' AND CommandLine ILIKE '%disable%')
