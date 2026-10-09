-- Title: Suspicious HH.EXE Execution
-- ID: e8a95b5e-c891-46e2-b33a-93937d3abc31
-- Status: test
-- Level: high
-- Author: Maxim Pavlunin
-- Date: 2020-04-01
-- Tags: attack.execution, attack.initial-access, attack.stealth, attack.t1047, attack.t1059.001, attack.t1059.003, attack.t1059.005, attack.t1059.007, attack.t1218, attack.t1218.001, attack.t1218.010, attack.t1218.011, attack.t1566, attack.t1566.001
-- Description: Detects a suspicious execution of a Microsoft HTML Help (HH.exe)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((OriginalFileName = 'HH.exe') OR (Image ILIKE '%\\hh.exe')) AND ((CommandLine ILIKE '%.application%' OR CommandLine ILIKE '%\\AppData\\Local\\Temp\\%' OR CommandLine ILIKE '%\\Content.Outlook\\%' OR CommandLine ILIKE '%\\Downloads\\%' OR CommandLine ILIKE '%\\Users\\Public\\%' OR CommandLine ILIKE '%\\Windows\\Temp\\%')))
