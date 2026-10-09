-- Title: Detected Windows Software Discovery
-- ID: e13f668e-7f95-443d-98d2-1816a7648a7b
-- Status: test
-- Level: medium
-- Author: Nikita Nazarov, oscd.community
-- Date: 2020-10-16
-- Tags: attack.discovery, attack.t1518
-- Description: Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%\\reg.exe' AND (CommandLine ILIKE '%query%' AND CommandLine ILIKE '%\\software\\%' AND CommandLine ILIKE '%/v%' AND CommandLine ILIKE '%svcversion%'))
