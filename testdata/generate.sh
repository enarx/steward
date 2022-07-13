#!/usr/bin/env bash
printf "Generating CA key\n"
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out ca.key
printf "\nCA "
openssl pkey -noout -text -in ca.key

printf "\nGenerating CA certificate\n"
openssl req -new -x509 -days 9999 -config ca.conf -key ca.key -out ca.crt
printf "\nCA "
openssl x509 -noout -text -in ca.crt
