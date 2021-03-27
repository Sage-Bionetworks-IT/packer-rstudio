#!/bin/bash

# This script should run only ONCE.
# It is used provide the configurations for Apache and Rstudio 
# with the EC2 instance ID which is running the AMI

# In case I am bad at programming
set -e; set -u; set -o pipefail

EC2_INSTANCE_ID=$(/usr/bin/curl -s http://169.254.169.254/latest/meta-data/instance-id)
# the environment variable is used by the "synapser" R package to retrieve 
# user Synapse authentication token from AWS Parameter Store
SYNAPSE_ENV_VAR_STRING="SYNAPSE_TOKEN_AWS_SSM_PARAMETER_NAME=/service-catalog/synapse/cred/$EC2_INSTANCE_ID/odic-accesstoken"


# modify apache proxy config
sed -i "s/^.*<LocationMatch.*\/.*\/>.*$/<LocationMatch \/$EC2_INSTANCE_ID\/>/g" /etc/apache2/sites-available/proxy.conf
# set envirronment variable for Apache 
echo "export $SYNAPSE_ENV_VAR_STRING" >> /etc/apache2/envvars

# set environment variable for R
echo $SYNAPSE_ENV_VAR_STRING >> /etc/R/Renviron.site

systemctl restart apache2 
# there does not appear to be a need to restart RStudio server