#!/bin/bash

export APP_PATH=/opt/local/apps/apache_mod_openidc/
export DEBIAN_FRONTEND="noninteractive"


export APACHE_SITE_CONF=apache_app.conf
export APACHE_ENVARS=envars
export PORTS_CONF=ports.conf
export APP_WWW_DIR=app
export WWW_FILE_DIR=www/


create_cert(){

    KEY_OUT=/etc/ssl/private/apache-selfsigned.key
    CERT_OUT=/etc/ssl/certs/apache-selfsigned.crt


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


}


configure_apache(){
    echo "[+] Beginning Apache Config"

    a2enmod ssl
    a2enmod auth_openidc
    a2enmod rewrite
    a2enmod proxy
    a2enmod headers

    mkdir /var/www/${APP_WWW_DIR}
    chown -R $USER:$USER /var/www/${APP_WWW_DIR}
    chmod -R 755 /var/www/${APP_WWW_DIR}

    cp ${APP_PATH}/${APACHE_SITE_CONF} /etc/apache2/sites-available/${APACHE_SITE_CONF}
    cp ${APP_PATH}/${PORTS_CONF} /etc/apache2/${PORTS_CONF}
    cp ${APP_PATH}/${APACHE_ENVARS} /etc/apache2/${APACHE_ENVARS}

    cp -r ${APP_PATH}/${WWW_FILE_DIR} /var/www/${APP_WWW_DIR}/

    apache2ctl -S

    a2dissite 000-default.conf
    a2ensite ${APACHE_SITE_CONF}
    apache2ctl configtest

    /usr/sbin/apache2 -V

    systemctl is-enabled apache2.service
    systemctl enable apache2.service

    apachectl -DFOREGROUND

    apachectl -k stop
    apachectl -k restart

    echo "[+] Ending Apache Config"
}


update_ubuntu(){
    echo "[+] Beginning Ubuntu Update"
    apt-get update && apt-get -y upgrade
    apt-get install -y systemctl sudo python3 python3-pip apache2 libapache2-mod-auth-openidc php libapache2-mod-php
    sudo systemctl status apache2.service

    echo "[+] Ending Ubuntu Update"
}

update_ubuntu
create_cert
configure_apache