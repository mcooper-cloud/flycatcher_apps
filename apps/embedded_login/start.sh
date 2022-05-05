#!/bin/bash

export APP_PATH=/opt/local/apps/embedded_login/
export DEBIAN_FRONTEND="noninteractive"
export NGINX_CONF=nginx_proxy.conf
export DHPARAMS_CONF=nginx_ssl_params.conf
export GUNICORN_CONF=gunicorn.service

configure_gunicorn(){
    echo "[+] Beginning Gunicorn Config"
    cp ${APP_PATH}/${GUNICORN_CONF} /etc/systemd/system/${GUNICORN_CONF}
    systemctl start gunicorn
    systemctl enable gunicorn
    echo "[+] Ending Gunicorn Config"
}

create_cert(){

    KEY_OUT=/etc/ssl/private/nginx-selfsigned.key
    CERT_OUT=/etc/ssl/certs/nginx-selfsigned.crt
    DHPARAMS_OUT=/etc/ssl/certs/dhparam.pem

    DNS_NAME="localhost"
    COUNTRY="US"
    STATE="PA"
    LOCAL="Philadelphia"
    ORG="Pintail"
    ORG_UNIT="Strategic"
    EMAIL="support@example.com"

    openssl req \
        -newkey rsa:2048 \
        -x509 \
        -nodes \
        -keyout ${KEY_OUT} \
        -new \
        -out ${CERT_OUT} \
        -reqexts SAN \
        -extensions SAN \
        -config <(cat /usr/lib/ssl/openssl.cnf \
            <(printf '
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
')) \
        -sha256 \
        -days 3650

    sudo openssl dhparam -out ${DHPARAMS_OUT} 2048

}

configure_nginx(){
    echo "[+] Beginning Nginx Config"
    cp ${APP_PATH}/${DHPARAMS_CONF} /etc/nginx/snippets/${DHPARAMS_CONF} 
    rm /etc/nginx/sites-enabled/default
    cp ${APP_PATH}/${NGINX_CONF} /etc/nginx/sites-available/${NGINX_CONF}
    ln -s /etc/nginx/sites-available/${NGINX_CONF} /etc/nginx/sites-enabled/
    nginx -g 'daemon off;'
    echo "[+] Ending Nginx Config"
}

update_ubuntu(){
    echo "[+] Beginning Ubuntu Update"
    REQS_PATH="${APP_PATH}/requirements.txt"
    apt-get update && apt-get -y upgrade
    apt-get install -y systemctl sudo nginx gunicorn python3 python3-pip
    pip3 install -r ${REQS_PATH} --upgrade
    echo "[+] Ending Ubuntu Update"
}

update_ubuntu
configure_gunicorn
create_cert
configure_nginx
