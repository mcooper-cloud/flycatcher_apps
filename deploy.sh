#!/bin/bash


##############################################################################
##############################################################################
##
## this script reads in an env file that should have the following 
## exported environment variables:
##
##        STACK_NAME = the name of the stack to be deployed
##        REGION = the region to deploy the stack within
##        STAGE_TEMPLATE = should cloudformation templates be staged in S3 (1|0)
##        WORKING_DIR = directory the deployment should occur within
##        INFRA_PATH = path to IaC template file directory
##        PARAM_PATH = path to IaC parameter file directory
##        CF_TEMPLATE_PATH = path to specific IaC template file 
##        CF_PARAM_PATH = path to specific IaC parameter file
##        LOG_PATH = path where logs should be stored
##
##############################################################################
##############################################################################


##############################################################################
##############################################################################
##
## MAGIC NUMBERS
##
##############################################################################
##############################################################################


ARG_NUMBER=1


##############################################################################
##############################################################################
##
## USAGE
##
##############################################################################
##############################################################################


usage(){
    if [ $# -lt $ARG_NUMBER ]; then
        echo "Usage: "
        echo "$0 \ "
        echo "  --env-file [ENV_FILE_PATH] \ "
        exit 1
    fi
}


##############################################################################
##############################################################################
##
## PARSE ARGS
##
##############################################################################
##############################################################################


parse_args(){
    while [[ $# > 1 ]];
    do
        key="$1"

        case $key in
            --env-file)
            ENV_FILE="$2"
            shift # past argument
            ;;
            *)
            # unknown option
            ;;
        esac
        shift
    done
}


##############################################################################
##############################################################################
##
## Prep logs
##
##############################################################################
##############################################################################


prep_logs(){

    ts=$(date +"%Y_%m_%d_%T" | sed -e 's/:/_/g')
    LP="${LOG_PATH}/${STACK_NAME}/${ts}"

    mkdir -p $LP

    VALIDATION_LOG="${LP}/template_validation.txt"
    EVENT_LOG="${LP}/event_log.txt"
    OUTPUT_LOG="${LP}/output_log.txt"

    ERR_VALIDATION_LOG="${LP}/err_template_validation.txt"
    ERR_EVENT_LOG="${LP}/err_event_log.txt"
    ERR_OUTPUT_LOG="${LP}/err_output_log.txt"


}


##############################################################################
##############################################################################
##
## STAGE
##
##############################################################################
##############################################################################


stage_template(){

    KEY="cloudformation/$CF_TEMPLATE_PATH"
    export S3_URL="https://s3.amazonaws.com/${STAGING_BUCKET_NAME}/${KEY}"
    echo "[+] $(date) - Staging CloudFormation template ... $S3_URL"
    aws s3api put-object --bucket $STAGING_BUCKET_NAME --key $KEY --body $CF_TEMPLATE_PATH

}


##############################################################################
##############################################################################
##
## VALIDATE
##
##############################################################################
##############################################################################


validate_template(){
    echo "[+] $(date) - Validating CloudFormation template ... $CF_TEMPLATE_PATH"
    echo "[+] $(date) - Writing validation log to ${VALIDATION_LOG}"

    if [ ${STAGE_TEMPLATE} -gt 0 ];
    then
        aws cloudformation validate-template \
            --template-url $S3_URL \
            --region $REGION > $VALIDATION_LOG 2> $ERR_VALIDATION_LOG
    else
        aws cloudformation validate-template \
            --template-body 'file://'$CF_TEMPLATE_PATH \
            --region $REGION > $VALIDATION_LOG 2> $ERR_VALIDATION_LOG
    fi

    if [ $? -gt 0 ]
    then
        cat $VALIDATION_LOG;
        cat $ERR_VALIDATION_LOG;
    fi

}


##############################################################################
##############################################################################
##
## DEPLOY STACK
##
##############################################################################
##############################################################################


deploy_stack(){

    ##
    ## set CAPABILITY_NAMED_IAM to avoid possible
    ## failures if IAM resources need to be created ... this setting
    ## could be considered low security and removed if IAM resources
    ## are not needed (the intention here is to genearlize)
    ##
    ## and setting CAPABILITY_AUTO_EXPAND to support use of nested
    ## cloudformation modules
    ##

    echo "[+] $(date) - Deploying CloudFormation stack ... $STACK_NAME"

    if [ ${STAGE_TEMPLATE} -gt 0 ];
    then
        aws cloudformation create-stack \
            --template-url $S3_URL \
            --parameter 'file://'$CF_PARAM_PATH \
            --stack-name $STACK_NAME \
            --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
            --region $REGION
    else
        aws cloudformation create-stack \
            --template-body 'file://'$CF_TEMPLATE_PATH \
            --parameter 'file://'$CF_PARAM_PATH \
            --stack-name $STACK_NAME \
            --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
            --region $REGION
    fi

}


##############################################################################
##############################################################################
##
## WAIT on STACK CREATE
##
##############################################################################
##############################################################################


wait_stack_create(){
    echo "[+] $(date) - Waiting for stack-create-complete ... $STACK_NAME"    
    aws cloudformation wait stack-create-complete \
        --stack-name $STACK_NAME \
        --region $REGION
}


##############################################################################
##############################################################################
##
## DESCRIBE EVENTS
##
##############################################################################
##############################################################################


describe_events(){
    echo "[+] $(date) - Describing stack events ... $STACK_NAME"
    echo "[+] $(date) - Writing event log to ${EVENT_LOG}"

    aws cloudformation describe-stack-events \
        --stack-name $STACK_NAME \
        --region $REGION > $EVENT_LOG 2> $ERR_EVENT_LOG
}


##############################################################################
##############################################################################
##
## GET STACK OUTPUTS
##
##############################################################################
##############################################################################


get_stack_outputs(){
    echo "[+] $(date) - Describing stack outputs ... $STACK_NAME"
    echo "[+] $(date) - Writing output log to ${OUTPUT_LOG}"

    aws cloudformation describe-stacks \
        --stack-name $STACK_NAME  \
        --query "Stacks[0].Outputs" \
        --region $REGION \
        --output json > $OUTPUT_LOG 2> $ERR_OUTPUT_LOG
}


##############################################################################
##############################################################################
##
## MAIN
##
##############################################################################
##############################################################################


main(){

    prep_logs

    if [ ${STAGE_TEMPLATE} -gt 0 ];
    then
        stage_template
    fi

    if ! validate_template; then
        echo "[-] $(date) - Invalid CloudFormation template ... exiting"
        return 1
    else
        deploy_stack
        if ! wait_stack_create; then
            echo "[-] $(date) - Stack create failed ... "
            describe_events
            ##
            ## this scenario leaves an orphaned failed stack 
            ## either manually teardown, or run the teardown.sh
            ##
            return 1

        else
            echo "[+] $(date) - Stack create complete ... "
            describe_events
            get_stack_outputs
            echo "[+] $(date) - SUCCESS! Stack deployment complete."
            return 0
        fi
    fi
}


usage $@
parse_args $@

source $ENV_FILE
main

