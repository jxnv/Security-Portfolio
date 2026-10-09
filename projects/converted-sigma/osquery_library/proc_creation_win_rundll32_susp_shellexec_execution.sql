-- Title: Suspicious Usage Of ShellExec_RunDLL
-- ID: d87bd452-6da1-456e-8155-7dc988157b7d
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-01
-- Tags: attack.stealth
-- Description: Detects suspicious usage of the ShellExec_RunDLL function to launch other commands as seen in the the raspberry-robin attack
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%ShellExec_RunDLL%') AND ((CommandLine LIKE '%\\Desktop\\%' OR CommandLine LIKE '%\\Temp\\%' OR CommandLine LIKE '%\\Users\\Public\\%' OR CommandLine LIKE '%comspec%' OR CommandLine LIKE '%iex%' OR CommandLine LIKE '%Invoke-%' OR CommandLine LIKE '%msiexec%' OR CommandLine LIKE '%odbcconf%' OR CommandLine LIKE '%regsvr32%')))
