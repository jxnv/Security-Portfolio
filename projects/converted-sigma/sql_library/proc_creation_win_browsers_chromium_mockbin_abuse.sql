-- Title: Chromium Browser Headless Execution To Mockbin Like Site
-- ID: 1c526788-0abe-4713-862f-b520da5e5316
-- Status: test
-- Level: high
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-09-11
-- Tags: attack.execution
-- Description: Detects the execution of a Chromium based browser process with the "headless" flag and a URL pointing to the mockbin.org service (which can be used to exfiltrate data).
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%--headless%') AND ((Image ILIKE '%\\brave.exe' OR Image ILIKE '%\\chrome.exe' OR Image ILIKE '%\\msedge.exe' OR Image ILIKE '%\\opera.exe' OR Image ILIKE '%\\vivaldi.exe')) AND ((CommandLine ILIKE '%://run.mocky%' OR CommandLine ILIKE '%://mockbin%')))
