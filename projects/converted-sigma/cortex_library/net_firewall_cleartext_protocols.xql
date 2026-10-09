// Title: Cleartext Protocol Usage
// ID: d7fb8f0e-bd5f-45c2-b467-19571c490d7e
// Status: stable
// Level: low
// Author: Alexandr Yampolskyi, SOC Prime, Tim Shelton
// Date: 2019-03-26
// Tags: attack.credential-access
// Description: Ensure that all account usernames and authentication credentials are transmitted across networks using encrypted channels.
// Ensure that an encryption is used for all sensitive information in transit. Ensure that an encrypted channels is used for all administrative account access.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((dst_port = 8080 or dst_port = 21 or dst_port = 80 or dst_port = 23 or dst_port = 50000 or dst_port = 1521 or dst_port = 27017 or dst_port = 3306 or dst_port = 1433 or dst_port = 11211 or dst_port = 15672 or dst_port = 5900 or dst_port = 5901 or dst_port = 5902 or dst_port = 5903 or dst_port = 5904)) and (((action = "forward" or action = "accept" or action = 2)) or (blocked = "false")))
