-- Title: Capabilities Discovery - Linux
-- ID: d8d97d51-122d-4cdd-9e2f-01b4b4933530
-- Status: test
-- Level: low
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-28
-- Tags: attack.discovery, attack.t1083
-- Description: Detects usage of "getcap" binary. This is often used during recon activity to determine potential binaries that can be abused as GTFOBins or other.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%/getcap' AND CommandLine ILIKE '% -r %')
