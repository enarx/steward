#!/usr/bin/env bash
printf "Generating CA key\n"
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out ca.key
printf "\nCA "
openssl pkey -noout -text -in ca.key

printf "\nGenerating CA certificate\n"
openssl req -new -x509 -config ca.conf -key ca.key -out ca.crt
printf "\nCA "
openssl x509 -noout -text -in ca.crt

printf "\nGenerating Server key\n"
openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -out server.key
printf "\nServer "
openssl pkey -noout -text -in server.key

printf "\nGenerating Server Certificate Signing Request\n"
openssl req -new -config server.conf -key server.key -out server.csr
printf "\nServer "
openssl req -text -in server.csr

printf "\nGenerating Server Certificate\n"
openssl x509 -req -days 9999 -CAcreateserial -CA ca.crt -CAkey ca.key -in server.csr -out server.crt -extfile server.conf -extensions server_crt
printf "\nServer "
openssl x509 -noout -text -in server.crt
