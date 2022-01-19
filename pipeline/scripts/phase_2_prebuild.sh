#!/bin/bash

echo "Exit status $?"
echo "[+] $(date) - Entered STAGE 1 PREBUILD - phase 2 prebuild"

ENV_SH_PATH=$CODEBUILD_SRC_DIR/$ENV_PATH/$ENV_SH
source $ENV_SH_PATH

main(){
    get_pipeline_stack_outputs
    get_secrets_params

    auth0_export "a0export" "a0export"
    ls -lah
}

main