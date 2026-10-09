-- Title: PowerShell Download and Execution Cradles
-- ID: 85b0b087-eddf-4a2b-b033-d771fa2b9775
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-24
-- Tags: attack.execution, attack.t1059
-- Description: Detects PowerShell download and execution cradles.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.DownloadString(%' OR CommandLine LIKE '%.DownloadFile(%' OR CommandLine LIKE '%Invoke-WebRequest %' OR CommandLine LIKE '%iwr %' OR CommandLine LIKE '%Invoke-RestMethod %' OR CommandLine LIKE '%irm %')) AND ((CommandLine LIKE '%;iex $%' OR CommandLine LIKE '%| IEX%' OR CommandLine LIKE '%|IEX %' OR CommandLine LIKE '%I`E`X%' OR CommandLine LIKE '%I`EX%' OR CommandLine LIKE '%IE`X%' OR CommandLine LIKE '%iex %' OR CommandLine LIKE '%IEX (%' OR CommandLine LIKE '%IEX(%' OR CommandLine LIKE '%Invoke-Expression%')))
