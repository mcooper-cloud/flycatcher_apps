#!/bin/bash

echo "Exit status $?"
echo "[+] $(date) - Entered STAGE 1 PREBUILD - phase 1 install"

ENV_SH_PATH=$CODEBUILD_SRC_DIR/$ENV_PATH/$ENV_SH
source $ENV_SH_PATH

install_auth0_deploy_cli(){
    echo "[+] Installing Auth0 Deploy CLI in ${CODEBUILD_SRC_DIR}/${AUTH0_DEPLOY_PATH}"
    cd $CODEBUILD_SRC_DIR/$AUTH0_DEPLOY_PATH
    npm install
    
    echo "[+] Installing Auth0 Deploy CLI in ${CODEBUILD_SRC_DIR}/${AUTH0_EXPORT_PATH}"
    cd $CODEBUILD_SRC_DIR/$AUTH0_EXPORT_PATH
    npm install
}

install_configure(){
    pip3 install -r requirements.txt
}

config(){
    ./configure.py --config $CONFIG_PATH
}

install_configure
config

##
## re-source our env file to get post-config
## values into the environment
##
source $ENV_SH_PATH
install_auth0_deploy_cli