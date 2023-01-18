#!/bin/bash

function export_env(){

    echo "[+] $(date) - Exporting Global ENV"
    DATE_STRING=$(date | sed -e 's/ /_/g' | sed -e 's/:/_/g')
    export PHASE_START=$DATE_STRING
    echo "[+] $(date) PHASE_START: $PHASE_START"

    export CONFIG_PATH="config/app_config.conf"


    export PROJECT_NAME="{{ ProjectName }}"
    export ENVIRONMENT="{{ EnvironmentName }}"
    export SYSTEM_NUMBER="{{ SystemNumber }}"

    export PIPELINE_STACK_NAME="{{ PipelineStackName }}"
    export APP_STACK_NAME="{{ AppStackName }}"

    ##
    ## env paths
    ##
    export APP_ENV_PATH="{{ AppEnvPath }}"

    ##
    ## Auth0 paths
    ##
    export AUTH0_EXPORT_PATH={{ Auth0ExportPath }}
    export AUTH0_DEPLOY_PATH={{ Auth0DeployPath }}
    export AUTH0_TENANT_PATH={{ Auth0TenantPath }}
    export AUTH0_TENANT_YAML={{ Auth0TenantYAML }}

    ##
    ## An API definition will be created in Auth0
    ## using this identifier
    ##
    export AUTH0_API_AUDIENCE={{ Auth0Audience }}

    ##
    ## application paths
    ##
    export WEB_APP_PATH="{{ WebAppBuildPath }}"

    ##
    ## application color and branding
    ##
    export PAGE_BACKGROUND_COLOR="{{ PageBackgroundColor }}"
    export PRIMARY_COLOR="{{ PrimaryColor }}"
    export LOGO_URL="{{ LogoURL }}"

    ##
    ## these are the names of the Cloudformation outputs
    ## that we can dynamically retrieve from our pipeline deployment
    ##
    export STAGING_BUCKET_NAME_OUTPUT="ArtifactBucketName"

    ##
    ## Auth0 parameters and secrets
    ##
    export AUTH0_CLIENT_ID_SM="${PROJECT_NAME}-${ENVIRONMENT}-${SYSTEM_NUMBER}-AUTH0_MGMT_CLIENT_ID"
    export AUTH0_CLIENT_SECRET_SM="${PROJECT_NAME}-${ENVIRONMENT}-${SYSTEM_NUMBER}-AUTH0_MGMT_CLIENT_SECRET"
    export AUTH0_DOMAIN_PARAM="${PROJECT_NAME}-${ENVIRONMENT}-${SYSTEM_NUMBER}-AUTH0_DOMAIN"
    export AUTH0_MGMT_API_ENDPOINT_PARAM="${PROJECT_NAME}-${ENVIRONMENT}-${SYSTEM_NUMBER}-AUTH0_MGMT_API_ENDPOINT"

    ##
    ## Auth0 parameters retrieved from the app stack
    ##
    export AUTH0_CALLBACK_URL_OUTPUT="Auth0CallbackURL"
    export AUTH0_LOGOUT_URL_OUTPUT="Auth0LogoutURL"

    export WEB_APP_HTTP_URL_OUTPUT="WebAppHTTPURL"

}


##############################################################################
##############################################################################
##
## generic get outputs from cloudformation stacks
##
##############################################################################
##############################################################################


function get_cf_outputs(){
    export CF_JSON=$(
        aws cloudformation describe-stacks \
            --stack-name $1  \
            --query "Stacks[0].Outputs" \
            --output json
    )
}


##############################################################################
##############################################################################
##
## get outputs from the supporting pipeline cloudformation stack
##
##############################################################################
##############################################################################


function get_pipeline_stack_outputs(){

    ##
    ## Pipeline stack outputs
    ## ... this is where we'll get Auth0 variables
    ##
    echo "[+] Getting outputs from stack ${PIPELINE_STACK_NAME}"

    get_cf_outputs $PIPELINE_STACK_NAME

    echo "[+] Cloudformation outputs for ${STACK_NAME}"
    echo ${CF_JSON} | jq -rc '.[]'

    get_json_output $STAGING_BUCKET_NAME_OUTPUT STAGING_BUCKET_NAME
    echo "[+] Staging bucket name: ${STAGING_BUCKET_NAME}"

}

function get_app_stack_outputs(){
    ##
    ## staging bucket stack outputs
    ## ... this is where we'll get the bucket name
    ##
    get_cf_outputs $APP_STACK_NAME

    get_json_output $AUTH0_CALLBACK_URL_OUTPUT AUTH0_CALLBACK_URL
    echo "[+] Auth0 Callback URL: ${AUTH0_CALLBACK_URL}"

    get_json_output $AUTH0_LOGOUT_URL_OUTPUT AUTH0_LOGOUT_URL
    echo "[+] Auth0 Logout URL: ${AUTH0_LOGOUT_URL}"

    get_json_output $WEB_APP_HTTP_URL_OUTPUT WEB_APP_HTTP_URL
    echo "[+] Web App HTTP URL: ${WEB_APP_HTTP_URL}"

}


##############################################################################
##############################################################################
##
## get Secrets Manager and SSM Parameter Store values
##
##############################################################################
##############################################################################


function get_secrets_params(){
    get_secret $AUTH0_CLIENT_ID_SM AUTH0_CLIENT_ID
    echo "[+] Auth0 Client ID: ${AUTH0_CLIENT_ID}"

    get_secret $AUTH0_CLIENT_SECRET_SM AUTH0_CLIENT_SECRET
    echo "[+] Auth0 Client Secret: ********$(echo ${AUTH0_CLIENT_SECRET} | grep -o '....$')"

    get_parameter $AUTH0_DOMAIN_PARAM AUTH0_DOMAIN
    echo "[+] Auth0 Domain: ${AUTH0_DOMAIN}"

    get_parameter $AUTH0_MGMT_API_ENDPOINT_PARAM AUTH0_MGMT_API_ENDPOINT
    echo "[+] Auth0 Management API Endpoint: ${AUTH0_MGMT_API_ENDPOINT}"

    export AUTH0_SUBDOMAIN=$(echo ${AUTH0_DOMAIN} | cut -d'.' -f1)
    echo "[+] Auth0 Subdomain: ${AUTH0_SUBDOMAIN}"
}


##############################################################################
##############################################################################
##
## generic get output value from CF_JSON
##
##############################################################################
##############################################################################


function get_json_output(){
    echo "[+] Retrieving JSON value $1"
    local value=$(echo ${CF_JSON} | jq --arg VAR ${1} -rc '.[] | select(.OutputKey==$VAR) | .OutputValue')
    export $2=$value
    echo "[+] Value: ${value}"
}


##############################################################################
##############################################################################
##
## sync local directory w/ S3 path
##
##############################################################################
##############################################################################


function s3_sync(){

    LOCAL_DIR=$1
    BUCKET=$2
    S3_PATH=$3

    aws s3 sync ${LOCAL_DIR} s3://${BUCKET}/${S3_PATH}

}


##############################################################################
##############################################################################
##
## generic get secrets from AWS Secrets Manager
##
##############################################################################
##############################################################################


function get_secret(){
    echo "[+] Retrieving secret $1"
    local value=$(aws secretsmanager get-secret-value --secret-id $1 --query SecretString --output text)
    export $2=$value
}


##############################################################################
##############################################################################
##
## generic get parameter from AWS SSM Parameter Store
##
##############################################################################
##############################################################################


function get_parameter(){
    echo "[+] Retrieving parameter $1"
    local value=$(aws ssm get-parameter --name $1 --query Parameter.Value --output text)
    export $2=$value
}


##############################################################################
##############################################################################
##
## deploy the Auth0 tenant
##
##############################################################################
##############################################################################


function auth0_deploy(){

    echo "[+]"
    echo "[+]"
    echo "[+] Auth0 Deploy Starts Here"
    echo "[+]"
    echo "[+]"

    cd $AUTH0_DEPLOY_PATH

    export NODE_PATH=$(npm root -g)

    export INPUT_PATH=$1

    echo "[+] Node version $(node --version)"
    echo "[+] NPM version $(npm --version)"
    echo "[+] NPM root $(npm root -g)"

    npm start

    cd $CODEBUILD_SRC_DIR

}


##############################################################################
##############################################################################
##
## export the Auth0 tenant data and store in S3 staging bucket
##
##############################################################################
##############################################################################


function auth0_export(){

    echo "[+]"
    echo "[+]"
    echo "[+] Auth0 Export Starts Here"
    echo "[+]"
    echo "[+]"

    cd $AUTH0_EXPORT_PATH

    export NODE_PATH=$(npm root -g)

    export OUTPUT_FOLDER=$1
    export BASE_PATH=$2

    ts=$(date +"%Y_%m_%d_%T" | sed -e 's/:/_/g')
    ZIP_PACKAGE_NAME="${ts}_a0export.zip"

    echo "[+] Node version $(node --version)"
    echo "[+] NPM version $(npm --version)"
    echo "[+] NPM root $(npm root -g)"

    ##
    ## this npm start command triggers the auth0-deploy-cli
    ##
    npm start

    zip -r $ZIP_PACKAGE_NAME $OUTPUT_FOLDER 

    aws s3api put-object \
        --bucket $STAGING_BUCKET_NAME \
        --key $OUTPUT_FOLDER/$ZIP_PACKAGE_NAME \
        --body $ZIP_PACKAGE_NAME

    cd $CODEBUILD_SRC_DIR

}


export_env
