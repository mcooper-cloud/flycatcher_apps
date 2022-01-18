#!/usr/bin/env python3

'''

    Read from a config file or a directory of config files and use 
    values parsed from the config file to render data into a single 
    Jinja template or a directory of Jinja templates

'''

import os
import argparse
from configparser import ConfigParser, ExtendedInterpolation
import jinja2
import json


###############################################################################
###############################################################################
##
## Arguments - allows user to call from command line
##
###############################################################################
###############################################################################


class Args(object):

    parser = argparse.ArgumentParser(description='Pipeline deployment utility')

    parser.add_argument(
        '--config', '--config-file', '-c',
        dest='config', 
        nargs=1, 
        help='Path to a the config file or directory containing multiple config files'
    )

    def print_help(self):
        self.parser.print_help()
        exit(1)
        return

    def parse(self):
        args = self.parser.parse_args()
        return args


###########################################################################
###########################################################################
##
## lambda handler
##
###########################################################################
###########################################################################


class ConfigBuilder(object):

    def __init__(self, config=None):

        self.exit_code = 0

        if config is not None:
            self.config = config


    ##########################################################################
    ##########################################################################
    ##
    ## Parse
    ##
    ##########################################################################
    ##########################################################################


    def parse_config(self):

        path = self.config

        config_list = []

        if os.path.isfile(path):

            print('[+] Using config file {}'.format(path))
            config_list.append(path)


        elif os.path.isdir(path):

            print('[+] Using config file path {}'.format(path))

            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:

                    print('[+] Found config file {}'.format(os.path.join(path, name)))

                    ##
                    ## handle multi-config here
                    ##
                    config_list.append(os.path.join(path, name))


        for c in sorted(config_list):
            self.build(config=c)


        return


    ##########################################################################
    ##########################################################################
    ##
    ## Build
    ##
    ##########################################################################
    ##########################################################################


    def build(self, config=None):

        if config is not None:

            ##
            ## option names of interest found in config file
            ##
            paths_section_name = 'CONFIG_PATHS'
            params_section_name = 'CONFIG_PARAMS'

            ##
            ## option names within CONFIG_PATHS
            ##
            param_path_option_name = 'ParameterPath'
            output_option_name = 'OutputPath'

            ##
            ## start parsing config
            ##

            conf = ConfigParser(interpolation=ExtendedInterpolation())
            conf.optionxform = str
            conf.read(config)

            working_dir = os.getcwd()
            out_path = None


            ##
            ## establish kwargs from config values
            ##
            kwargs = {}

            if params_section_name in conf.sections():

                for o in conf[params_section_name]:
                    ##
                    ## strip leading and traling quotes
                    ##
                    s = conf[params_section_name][o].lstrip('\"')
                    s = s.rstrip('\"')
                    kwargs[o] = s

            else:
                print('[-] Error: no {} section header found in config'.format(params_section_name))
                exit(1)


            print('[+] Rendering jinja templates with **kwargs\n{}'.format(kwargs))


            ##
            ## iterate through parameter files
            ##
            if paths_section_name in conf.sections():

                if param_path_option_name in conf[paths_section_name]:

                    param_file_list = []

                    try:
                        s = conf[paths_section_name][param_path_option_name]
                        print('[+] Using arameter paths:\n{}'.format(s))
                        path_list = json.loads(s)

                    except Exception as e:

                        print('[-] ParameterPath config option must be a list: {}'.format(e))
                        exit(1)

                    ##
                    ## set output path if it's in the config ... 
                    ## otherwise skip it
                    ##
                    if output_option_name in conf[paths_section_name]:
                        out_path = conf[paths_section_name][output_option_name]

                    for path in path_list:

                        path = os.path.join(working_dir, path)

                        if os.path.isfile(path):

                            print('[+] Using param file {}'.format(path))
                            param_file_list.append(path)


                        elif os.path.isdir(path):

                            print('[+] Using param file path {}'.format(path))

                            for root, dirs, files in os.walk(path, topdown=False):
                                for name in files:

                                    print('[+] Found config file {}'.format(os.path.join(path, name)))

                                    ##
                                    ## handle multi-config here
                                    ##
                                    param_file_list.append(os.path.join(path, name))


                for p in param_file_list:

                    print('[+] Using parameter file {}'.format(p))

                    try:
                        with open(p) as file_:

                            print('[+] Reading jinja template {}'.format(p))
                            template = jinja2.Template(file_.read())

                            template_data = template.render(**kwargs)

                            if out_path is not None:

                                if not os.path.exists(out_path):
                                    os.makedirs(out_path)

                                basename = os.path.basename(p)
                                param_out_file = os.path.join(out_path, basename)

                            else:
                                param_out_file = p

                            print('[+] Writing template output to {}'.format(param_out_file))
                            with open(param_out_file, 'wb+') as f:
                                f.write(b'%b'%template_data.encode())

                    except Exception as e:
                        print('[-] Jinja2 render exception: {}'.format(e))



###########################################################################
###########################################################################
##
## lambda handler
##
###########################################################################
###########################################################################


def lambda_handler(event, context):
    ##
    ## Lambda handler
    ##

    path = event['config']

    builder = ConfigBuilder(config=event['config'])
    builder.parse_config()

    return


###########################################################################
###########################################################################
##
## MAIN - install boto3 and AWS CLI to test locally
##
###########################################################################
###########################################################################

if __name__ == '__main__':

    ##########################################################################
    ##########################################################################
    ##
    ## parse arguments
    ##
    ##########################################################################
    ##########################################################################

    a = Args()
    args = a.parse()

    config = args.config[0] if args.config else None


    ##########################################################################
    ##########################################################################
    ##
    ## exit on missing flags
    ##
    ##########################################################################
    ##########################################################################


    if config is None:
        print('[-] Requires a config file via --config argument')
        a.print_help()
        exit(1)


    ##########################################################################
    ##########################################################################
    ##
    ## call the handler
    ##
    ##########################################################################
    ##########################################################################

    context = None
    event = {
        'config' : config
    }

    lambda_handler(event, context)
