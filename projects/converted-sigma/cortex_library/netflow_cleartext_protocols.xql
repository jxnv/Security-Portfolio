// Title: Cleartext Protocol Usage Via Netflow
// ID: 7e4bfe58-4a47-4709-828d-d86c78b7cc1f
// Status: stable
// Level: low
// Author: Alexandr Yampolskyi, SOC Prime
// Date: 2019-03-26
// Tags: attack.credential-access
// Description: Ensure that all account usernames and authentication credentials are transmitted across networks using encrypted channels
// Ensure that an encryption is used for all sensitive information in transit.
// Ensure that an encrypted channels is used for all administrative account access.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((destination.port = 8080 or destination.port = 21 or destination.port = 80 or destination.port = 23 or destination.port = 50000 or destination.port = 1521 or destination.port = 27017 or destination.port = 1433 or destination.port = 11211 or destination.port = 3306 or destination.port = 15672 or destination.port = 5900 or destination.port = 5901 or destination.port = 5902 or destination.port = 5903 or destination.port = 5904))
