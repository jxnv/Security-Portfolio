-- Title: Suspicious Use of /dev/tcp
-- ID: 6cc5fceb-9a71-4c23-aeeb-963abe0b279c
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-10
-- Tags: attack.reconnaissance
-- Description: Detects suspicious command with /dev/tcp
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ("cat </dev/tcp/" OR "exec 3<>/dev/tcp/" OR "echo >/dev/tcp/" OR "bash -i >& /dev/tcp/" OR "sh -i >& /dev/udp/" OR "0<&196;exec 196<>/dev/tcp/" OR "exec 5<>/dev/tcp/" OR "(sh)0>/dev/tcp/" OR "bash -c 'bash -i >& /dev/tcp/" OR "echo -e '#!/bin/bash\\nbash -i >& /dev/tcp/")
