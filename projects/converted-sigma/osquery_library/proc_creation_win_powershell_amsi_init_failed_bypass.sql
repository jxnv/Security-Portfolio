-- Title: Potential AMSI Bypass Via .NET Reflection
-- ID: 30edb182-aa75-42c0-b0a9-e998bb29067c
-- Status: test
-- Level: high
-- Author: Markus Neis, @Kostastsale
-- Date: 2018-08-17
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects Request to "amsiInitFailed" that can be used to disable AMSI Scanning
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%System.Management.Automation.AmsiUtils%' AND CommandLine LIKE '%amsiInitFailed%')) OR ((CommandLine LIKE '%[Ref].Assembly.GetType%' AND CommandLine LIKE '%SetValue($null,$true)%' AND CommandLine LIKE '%NonPublic,Static%')))
