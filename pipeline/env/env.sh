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


export_env
