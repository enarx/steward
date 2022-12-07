#!/usr/bin/env bash
printf "Generating CA key\n"
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out ca.key
printf "\nCA "
openssl pkey -noout -text -in ca.key

printf "\nGenerating CA certificate\n"
openssl req -new -x509 -days 9999 -config ca.conf -key ca.key -out ca.crt
printf "\nCA "
openssl x509 -noout -text -in ca.crt

printf "\nGenerating test key\n"
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out test.key
printf "\nKey "
openssl pkey -noout -text -in test.key

printf "\nGenerating test cert request\n"
openssl req -new -config test.conf -key test.key -out test.csr

printf "\nSigning test cert request\n"
openssl x509 -req -in test.csr -days 9999 -CA ca.crt -extfile test.conf -CAkey ca.key -set_serial 99 -out test.crt
printf "\nCert "
openssl x509 -noout -text -in test.crt
