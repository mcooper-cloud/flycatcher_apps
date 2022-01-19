#!/bin/bash

echo "Exit status $?"
echo "[+] $(date) - Entered STAGE 1 PREBUILD - phase 3 build"

ENV_SH_PATH=$CODEBUILD_SRC_DIR/$ENV_PATH/$ENV_SH
source $ENV_SH_PATH

function app_deploy(){

    cd $CODEBUILD_SRC_DIR
    ./deploy.sh --env-file $APP_ENV_PATH

}

function app_teardown(){

    cd $CODEBUILD_SRC_DIR
    ./teardown.sh --env-file $APP_ENV_PATH

}

main(){

    get_pipeline_stack_outputs
    get_secrets_params

    ##
    ## stage web app
    ##
    s3_sync ./${WEB_APP_PATH} ${STAGING_BUCKET_NAME} ${WEB_APP_PATH}

    ##
    ## deploy the application stack because outputs from the app
    ## stack are dynamically inserted into the Auth0 config
    ##
    app_teardown
    app_deploy
    get_app_stack_outputs
    
    auth0_deploy "${CODEBUILD_SRC_DIR}/${AUTH0_TENANT_YAML}" "a0deploy"

}

main
