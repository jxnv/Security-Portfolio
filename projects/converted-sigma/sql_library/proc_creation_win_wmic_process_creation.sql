-- Title: Process Creation Attempt via Wmic.EXE
-- ID: 526be59f-a573-4eea-b5f7-f0973207634d
-- Status: test
-- Level: medium
-- Author: Michael Haag, Florian Roth (Nextron Systems), juju4, oscd.community
-- Date: 2019-01-16
-- Tags: attack.execution, attack.t1047, car.2016-03-002
-- Description: Detects the attempt to create a process via "wmic" with the "process call create" flag, which might
-- indicate an attempt to execute a malicious process on the compromised host. Adversaries may use
-- wmic to execute a process on the compromised host as part of their attack. This event is triggered on
-- on attempt and process creation can be either successful or unsuccessful.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%process%' AND CommandLine ILIKE '%call%' AND CommandLine ILIKE '%create%')) AND ((Image ILIKE '%\\wmic.exe') OR (OriginalFileName = 'wmic.exe')))
