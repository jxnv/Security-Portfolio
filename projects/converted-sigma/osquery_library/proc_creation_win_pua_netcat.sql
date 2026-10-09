-- Title: PUA - Netcat Suspicious Execution
-- ID: e31033fc-33f0-4020-9a16-faf9b31cbf08
-- Status: test
-- Level: high
-- Author: frack113, Florian Roth (Nextron Systems)
-- Date: 2021-07-21
-- Tags: attack.command-and-control, attack.t1095
-- Description: Detects execution of Netcat. Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -lvp %' OR CommandLine LIKE '% -lvnp%' OR CommandLine LIKE '% -l -v -p %' OR CommandLine LIKE '% -lv -p %' OR CommandLine LIKE '% -l --proxy-type http %' OR CommandLine LIKE '% -vnl --exec %' OR CommandLine LIKE '% -vnl -e %' OR CommandLine LIKE '% --lua-exec %' OR CommandLine LIKE '% --sh-exec %')) OR ((Image="*\\nc.exe" OR Image="*\\ncat.exe" OR Image="*\\netcat.exe")))
