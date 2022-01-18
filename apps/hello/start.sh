#!/bin/sh

APP_PATH=/opt/local/apps/hello/
cd $APP_PATH

##
## parse CLI options
##
while getopts d: FLAG
do
    case "${FLAG}" in
        d) DNS_NAME=${OPTARG}
        ;;
    esac
done

##
## verify option
##
if [ -z "$DNS_NAME" ]
then
    echo "Missing DNS name (-d) using localhost"
    DNS_NAME="localhost"
fi
echo "DNS name: $DNS_NAME"

function create_cert(){

    mkdir cert

    KEY_OUT=./cert/dev.key
    CERT_OUT=./cert/dev.crt

    DHPARAMS_OUT=/etc/ssl/certs/dhparam.pem

    DNS_NAME=$DNS_NAME
    COUNTRY="US"
    STATE="PA"
    LOCAL="Philadelphia"
    ORG="Pintail"
    ORG_UNIT="Strategic"
    EMAIL="support@example.com"


    cat <<EOF >> /etc/ssl/openssl.cnf 
[req]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn
[dn]
C = '${COUNTRY}'
ST = '${STATE}'
L = '${LOCAL}'
O = '${ORG}'
OU = '${ORG_UNIT}'
emailAddress = '${EMAIL}'
CN = '${DNS_NAME}'
[v3_req]
subjectAltName = @alt_names
[SAN]
subjectAltName = @alt_names
[alt_names]
DNS.1 = '${DNS_NAME}'
EOF

    openssl req \
        -newkey rsa:2048 \
        -x509 \
        -nodes \
        -keyout ${KEY_OUT} \
        -new \
        -out ${CERT_OUT} \
        -reqexts SAN \
        -extensions SAN \
        -sha256 \
        -days 3650 \
        -config /etc/ssl/openssl.cnf 

}

function update_alpine(){
    echo "[+] Beginning Alpine Update"
    apk update && apk upgrade

    if [[ "${LOADBALANCER_PORT}" -eq 443 ]]; then
        apk add openssl
        create_cert
    fi

    echo "[+] Ending Alpine Update"
}


function start_app(){
#    cd $APP_PATH
    npm install
    npm start
}


update_alpine
start_app