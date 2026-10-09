// Title: Suspicious Use of /dev/tcp
// ID: 6cc5fceb-9a71-4c23-aeeb-963abe0b279c
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-12-10
// Tags: attack.reconnaissance
// Description: Detects suspicious command with /dev/tcp
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ("cat </dev/tcp/" or "exec 3<>/dev/tcp/" or "echo >/dev/tcp/" or "bash -i >& /dev/tcp/" or "sh -i >& /dev/udp/" or "0<&196;exec 196<>/dev/tcp/" or "exec 5<>/dev/tcp/" or "(sh)0>/dev/tcp/" or "bash -c 'bash -i >& /dev/tcp/" or "echo -e '#!/bin/bash\\nbash -i >& /dev/tcp/")
