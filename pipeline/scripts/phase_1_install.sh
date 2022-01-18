#!/bin/bash

echo "Exit status $?"
echo "[+] $(date) - Entered STAGE 1 PREBUILD - phase 1 install"

ENV_SH_PATH=$CODEBUILD_SRC_DIR/$ENV_PATH/$ENV_SH
source $ENV_SH_PATH

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
