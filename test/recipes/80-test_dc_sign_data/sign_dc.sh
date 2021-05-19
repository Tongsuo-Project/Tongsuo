#!/bin/sh

set -e

O_EXE=`pwd`/$BLDTOP/apps
O_LIB=`pwd`/$BLDTOP

export PATH=$O_EXE:$PATH
export LD_LIBRARY_PATH=$O_LIB:$LD_LIBRARY_PATH

echo $DATADIR
which openssl

cd $DATADIR

rm -rf {newcerts,db,private,crl}
mkdir {newcerts,db,private,crl}
touch db/{index,serial}
echo 00 > db/serial

# ca
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out dc-ecc-root.key

openssl req -config openssl.cnf -new -key dc-ecc-root.key -out dc-ecc-root.csr -sha256 -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=root ca" -batch

openssl ca -selfsign -config openssl.cnf -in dc-ecc-root.csr -extensions v3_ca -days 3650 -out dc-ecc-root.crt -md sha256 -batch

# middle ca
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out dc-ecc-middle-ca.key

openssl req -config openssl.cnf -new -key dc-ecc-middle-ca.key -out dc-ecc-middle-ca.csr -sha256 -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=middle ca" -batch

openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -in dc-ecc-middle-ca.csr -out dc-ecc-middle-ca.crt -md sha256 -batch

cat dc-ecc-root.crt dc-ecc-middle-ca.crt > dc-ecc-chain-ca.crt

# server
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out dc-ecc-leaf.key

openssl req -config openssl_middleca.cnf -new -key dc-ecc-leaf.key -out dc-ecc-leaf.csr -sha256 -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=server" -batch

openssl ca -config openssl_middleca.cnf -extensions server_cert -days 3650 -in dc-ecc-leaf.csr -out dc-ecc-leaf.crt -md sha256 -batch

# client
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out dc-ecc-leaf-clientUse.key

openssl req -config openssl_middleca.cnf -new -key dc-ecc-leaf-clientUse.key -out dc-ecc-leaf-clientUse.csr -sha256 -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=client" -batch

openssl ca -config openssl_middleca.cnf -extensions usr_cert -days 3650 -in dc-ecc-leaf-clientUse.csr -out dc-ecc-leaf-clientUse.crt -md sha256 -batch

# server dc
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out dc-ecc-server-longterm.key

openssl delecred -new -server -sec 604800 -dc_key dc-ecc-server-longterm.key -out dc-ecc-server-longterm.dc -parent_cert dc-ecc-leaf.crt -parent_key dc-ecc-leaf.key -expect_verify_md sha256 -sha256

# client dc
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out dc-ecc-client-longterm.key

openssl delecred -new -client -sec 604800 -dc_key dc-ecc-client-longterm.key -out dc-ecc-client-longterm.dc -parent_cert dc-ecc-leaf-clientUse.crt -parent_key dc-ecc-leaf-clientUse.key -expect_verify_md sha256 -sha256

# server expire dc
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out dc-ecc-server-expire.key

openssl delecred -new -server -sec 1 -dc_key dc-ecc-server-expire.key -out dc-ecc-server-expire.dc -parent_cert dc-ecc-leaf.crt -parent_key dc-ecc-leaf.key -expect_verify_md sha256 -sha256

# client expire dc
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out dc-ecc-client-expire.key

openssl delecred -new -client -sec 1 -dc_key dc-ecc-client-expire.key -out dc-ecc-client-expire.dc -parent_cert dc-ecc-leaf-clientUse.crt -parent_key dc-ecc-leaf-clientUse.key -expect_verify_md sha256 -sha256

cp -r *.crt ../../certs
cp -r *.key ../../certs
cp -r *.dc ../../certs
