-- Title: Network Connection Initiated By Regsvr32.EXE
-- ID: c7e91a02-d771-4a6d-a700-42587e0b1095
-- Status: test
-- Level: medium
-- Author: Dmitriy Lifanov, oscd.community
-- Date: 2019-10-25
-- Tags: attack.execution, attack.stealth, attack.t1559.001, attack.t1218.010
-- Description: Detects a network connection initiated by "Regsvr32.exe"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Initiated = 'true' AND Image ILIKE '%\\regsvr32.exe')
