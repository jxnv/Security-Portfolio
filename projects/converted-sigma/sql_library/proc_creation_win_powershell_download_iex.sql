-- Title: PowerShell Download and Execution Cradles
-- ID: 85b0b087-eddf-4a2b-b033-d771fa2b9775
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-24
-- Tags: attack.execution, attack.t1059
-- Description: Detects PowerShell download and execution cradles.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%.DownloadString(%' OR CommandLine ILIKE '%.DownloadFile(%' OR CommandLine ILIKE '%Invoke-WebRequest %' OR CommandLine ILIKE '%iwr %' OR CommandLine ILIKE '%Invoke-RestMethod %' OR CommandLine ILIKE '%irm %')) AND ((CommandLine ILIKE '%;iex $%' OR CommandLine ILIKE '%| IEX%' OR CommandLine ILIKE '%|IEX %' OR CommandLine ILIKE '%I`E`X%' OR CommandLine ILIKE '%I`EX%' OR CommandLine ILIKE '%IE`X%' OR CommandLine ILIKE '%iex %' OR CommandLine ILIKE '%IEX (%' OR CommandLine ILIKE '%IEX(%' OR CommandLine ILIKE '%Invoke-Expression%')))
