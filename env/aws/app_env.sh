
export_env(){

    ##########################################################################
    ##########################################################################
    ##
    ## customize these lines
    ##
    ##########################################################################
    ##########################################################################


    export STACK_NAME="{{ AppStackName }}"
    export REGION='{{ Region }}'

    ##
    ## stage templates in S3?  1=yes, 0=no
    ##
    export STAGE_TEMPLATE=1

    ##########################################################################
    ##########################################################################
    ##
    ## DO NOT customize these lines
    ##
    ##########################################################################
    ##########################################################################


    export WORKING_DIR=$(pwd)
    export INFRA_PATH='infra/aws'
    export PARAM_PATH='infra/aws/params'
    export CF_TEMPLATE_PATH=$INFRA_PATH'/ecs/ecs.json'
    export CF_PARAM_PATH=$PARAM_PATH'/app_params.json'
    export LOG_PATH=$WORKING_DIR'/logs/'

}

export_env
