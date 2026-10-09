-- Title: New BgInfo.EXE Custom VBScript Registry Configuration
-- ID: 992dd79f-dde8-4bb0-9085-6350ba97cfb3
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-16
-- Tags: attack.persistence, attack.defense-impairment, attack.t1112
-- Description: Detects setting of a new registry value related to BgInfo configuration, which can be abused to execute custom VBScript via "BgInfo.exe"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (TargetObject ILIKE '%\\Software\\Winternals\\BGInfo\\UserFields\\%' AND Details ILIKE '4%')
