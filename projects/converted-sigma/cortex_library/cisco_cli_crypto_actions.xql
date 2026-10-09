// Title: Cisco Crypto Commands
// ID: 1f978c6a-4415-47fb-aca5-736a44d7ca3d
// Status: test
// Level: high
// Author: Austin Clark
// Date: 2019-08-12
// Tags: attack.credential-access, attack.defense-impairment, attack.t1553.004, attack.t1552.004
// Description: Show when private keys are being exported from the device, or when new certificates are installed
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ("crypto pki export" or "crypto pki import" or "crypto pki trustpoint")
