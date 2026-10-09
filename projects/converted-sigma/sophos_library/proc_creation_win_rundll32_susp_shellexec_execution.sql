-- Title: Suspicious Usage Of ShellExec_RunDLL
-- ID: d87bd452-6da1-456e-8155-7dc988157b7d
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-01
-- Tags: attack.stealth
-- Description: Detects suspicious usage of the ShellExec_RunDLL function to launch other commands as seen in the the raspberry-robin attack
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%ShellExec_RunDLL%') AND ((CommandLine ILIKE '%\\Desktop\\%' OR CommandLine ILIKE '%\\Temp\\%' OR CommandLine ILIKE '%\\Users\\Public\\%' OR CommandLine ILIKE '%comspec%' OR CommandLine ILIKE '%iex%' OR CommandLine ILIKE '%Invoke-%' OR CommandLine ILIKE '%msiexec%' OR CommandLine ILIKE '%odbcconf%' OR CommandLine ILIKE '%regsvr32%')))
