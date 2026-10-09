-- Title: Enable BPF Kprobes Tracing
-- ID: 7692f583-bd30-4008-8615-75dab3f08a99
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-25
-- Tags: attack.execution, attack.stealth
-- Description: Detects common command used to enable bpf kprobes tracing
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%echo 1 >%' AND CommandLine LIKE '%/sys/kernel/debug/tracing/events/kprobes/%') AND (CommandLine LIKE '%/myprobe/enable%' OR CommandLine LIKE '%/myretprobe/enable%'))
