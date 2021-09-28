# 使用BabaSSL签发SM2双证书

## mkcert.sh

~~~
export PATH=/usr/local/babassl-share/bin/:$PATH

rm -rf {newcerts,db,private,crl}
mkdir {newcerts,db,private,crl}
touch db/{index,serial}
echo 00 > db/serial

# sm2 ca
openssl ecparam -genkey -name SM2 -outform pem -out ca.key

openssl req -config ca.cnf -new -key ca.key -out ca.csr -sm3 -nodes -sigopt "sm2_id:1234567812345678" -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=root ca"

openssl ca -selfsign -config ca.cnf -in ca.csr -keyfile ca.key -extensions v3_ca -days 3650 -notext -out ca.crt -md sm3 -batch

# sm2 middle ca
openssl ecparam -genkey -name SM2 -out subca.key

openssl req -config ca.cnf -new -key subca.key -out subca.csr -sm3 -sigopt "sm2_id:1234567812345678" -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=sub ca"

openssl ca -config ca.cnf -extensions v3_intermediate_ca -days 3650 -in subca.csr -notext -out subca.crt -md sm3 -batch

cat ca.crt subca.crt > chain-ca.crt

# server sm2 double certs
openssl ecparam -name SM2 -out server_sm2.param

openssl req -config subca.cnf -newkey ec:server_sm2.param -nodes -keyout server_sign.key -sm3 -sigopt "sm2_id:1234567812345678" -new -out server_sign.csr -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=server sign"

openssl ca -config subca.cnf -extensions sign_req -days 3650 -in server_sign.csr -notext -out server_sign.crt -md sm3 -batch

openssl req -config subca.cnf -newkey ec:server_sm2.param -nodes -keyout server_enc.key -sm3 -sigopt "sm2_id:1234567812345678" -new -out server_enc.csr -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=server enc"

openssl ca -config subca.cnf -extensions enc_req -days 3650 -in server_enc.csr -notext -out server_enc.crt -md sm3 -batch

# client sm2 double certs
openssl ecparam -name SM2 -out client_sm2.param

openssl req -config subca.cnf -newkey ec:client_sm2.param -nodes -keyout client_sign.key -sm3 -sigopt "sm2_id:1234567812345678" -new -out client_sign.csr -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=client sign"

openssl ca -config subca.cnf -extensions sign_req -days 3650 -in client_sign.csr -notext -out client_sign.crt -md sm3 -batch

openssl req -config subca.cnf -newkey ec:client_sm2.param -nodes -keyout client_enc.key -sm3 -sigopt "sm2_id:1234567812345678" -new -out client_enc.csr -subj "/C=AA/ST=BB/O=CC/OU=DD/CN=client enc"

openssl ca -config subca.cnf -extensions enc_req -days 3650 -in client_enc.csr -notext -out client_enc.crt -md sm3 -batch
~~~

## ca.cnf

~~~
[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = ./
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/db/index
unique_subject	  = no
serial            = $dir/db/serial
RANDFILE          = $dir/private/random

# The root key and root certificate.
private_key       = $dir/ca.key
certificate       = $dir/ca.crt

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 365
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

req_extensions = v3_req

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = optional
stateOrProvinceName             = optional
localityName                    = optional
0.organizationName              = optional
organizationalUnitName          = optional
commonName                      = optional
emailAddress                    = optional

[ v3_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
delegationUsage = serverDelegation, clientDelegation

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
delegationUsage = serverDelegation, clientDelegation

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
~~~

## subca.cnf

~~~
[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = ./
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/db/index
unique_subject	  = no
serial            = $dir/db/serial
RANDFILE          = $dir/private/random

# The root key and root certificate.
private_key       = $dir/subca.key
certificate       = $dir/subca.crt

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sm3

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 365
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

req_extensions = v3_req

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = optional
stateOrProvinceName             = optional
localityName                    = optional
0.organizationName              = optional
organizationalUnitName          = optional
commonName                      = optional
emailAddress                    = optional

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
delegationUsage = serverDelegation, clientDelegation

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
delegationUsage = serverDelegation, clientDelegation

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning

[ sign_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature

[ enc_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = keyAgreement, keyEncipherment, dataEncipherment
~~~
