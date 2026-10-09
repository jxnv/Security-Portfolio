-- Title: Container Residence Discovery Via Proc Virtual FS
-- ID: 746c86fb-ccda-4816-8997-01386263acc4
-- Status: test
-- Level: low
-- Author: Seth Hanford
-- Date: 2023-08-23
-- Tags: attack.discovery, attack.t1082
-- Description: Detects potential container discovery via listing of certain kernel features in the "/proc" virtual filesystem
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%awk' OR Image ILIKE '%/cat' OR Image ILIKE '%grep' OR Image ILIKE '%/head' OR Image ILIKE '%/less' OR Image ILIKE '%/more' OR Image ILIKE '%/nl' OR Image ILIKE '%/tail')) AND ((CommandLine ILIKE '%/proc/2/%') OR (CommandLine ILIKE '%/proc/%' AND (CommandLine ILIKE '%/cgroup' OR CommandLine ILIKE '%/sched'))))
