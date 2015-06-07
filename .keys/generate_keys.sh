#!/bin/sh
# -*- coding: utf-8 -*-
# -----
# This script will generate the SSL-Keys, as described in
# https://github.com/ether/etherpad-lite/wiki/Providing-encrypted-web-access-to-Etherpad-Lite-using-SSL-certificates
#
# This should NOT be used in a real-life deployment.
#
# VALUES (can be changed):
# - the keys are valid for 9000 days (~24.6 years)
# - the etherpad-user is named 'ether'

KEY_DUR=9000
EPL_USER='ether'

# server-keys
openssl genrsa -des3 -out epl-server.key 4096
openssl req -new -key epl-server.key -out epl-server.csr
openssl x509 -req -days $KEY_DUR -in epl-server.csr -signkey epl-server.key -out epl-server.crt
openssl rsa -in epl-server.key -out epl-server.key.insecure
mv epl-server.key epl-server.key.secure
mv epl-server.key.insecure epl-server.key

# certificate authority

openssl genrsa -des3 -out own-ca.key 4096
openssl req -new -x509 -days $KEY_DUR -key own-ca.key -out own-ca.crt
openssl x509 -req -days $KEY_DUR -in epl-server.csr -CA own-ca.crt -CAkey own-ca.key -set_serial 001 -out epl-server.crt

# file permissions

chmod 400 epl-server.key
chown $EPL_USER epl-server.key
chmod 400 epl-server.crt
chown $EPL_USER epl-server.crt

# remove files

rm epl-server.key.secure
rm epl-server.csr
rm own-ca.key
#rm own-ca.crt
