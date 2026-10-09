-- Title: Linux Crypto Mining Indicators
-- ID: 9069ea3c-b213-4c52-be13-86506a227ab1
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-10-26
-- Tags: attack.impact, attack.t1496
-- Description: Detects command line parameters or strings often used by crypto miners
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '% --cpu-priority=%' OR CommandLine ILIKE '%--donate-level=0%' OR CommandLine ILIKE '% -o pool.%' OR CommandLine ILIKE '% --nicehash%' OR CommandLine ILIKE '% --algo=rx/0 %' OR CommandLine ILIKE '%stratum+tcp://%' OR CommandLine ILIKE '%stratum+udp://%' OR CommandLine ILIKE '%sh -c /sbin/modprobe msr allow_writes=on%' OR CommandLine ILIKE '%LS1kb25hdGUtbGV2ZWw9%' OR CommandLine ILIKE '%0tZG9uYXRlLWxldmVsP%' OR CommandLine ILIKE '%tLWRvbmF0ZS1sZXZlbD%' OR CommandLine ILIKE '%c3RyYXR1bSt0Y3A6Ly%' OR CommandLine ILIKE '%N0cmF0dW0rdGNwOi8v%' OR CommandLine ILIKE '%zdHJhdHVtK3RjcDovL%' OR CommandLine ILIKE '%c3RyYXR1bSt1ZHA6Ly%' OR CommandLine ILIKE '%N0cmF0dW0rdWRwOi8v%' OR CommandLine ILIKE '%zdHJhdHVtK3VkcDovL%'))
