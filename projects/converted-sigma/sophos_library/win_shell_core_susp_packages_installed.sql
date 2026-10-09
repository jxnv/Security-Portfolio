-- Title: Suspicious Application Installed
-- ID: 83c161b6-ca67-4f33-8ad0-644a0737cf07
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-14
-- Tags: attack.execution
-- Description: Detects suspicious application installed by looking at the added shortcut to the app resolver cache
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((EventID = 28115 AND (Name ILIKE '%Zenmap%' OR Name ILIKE '%AnyDesk%' OR Name ILIKE '%wireshark%' OR Name ILIKE '%openvpn%')) OR (EventID = 28115 AND (AppID ILIKE '%zenmap.exe%' OR AppID ILIKE '%prokzult ad%' OR AppID ILIKE '%wireshark%' OR AppID ILIKE '%openvpn%')))
