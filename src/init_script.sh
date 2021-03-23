#!/bin/bash

# This script is run ONCE at first boot to set up configuration apache and Rstudio

# In case I am bad at programming
set -e; set -u; set -o pipefail

EC2_INSTANCE_ID=$(/usr/bin/curl -s http://169.254.169.254/latest/meta-data/instance-id)
# the environment variable is used by the "synapser" R package to retrieve 
# user Synapse authentication token from AWS Parameter Store
SYNAPSE_ENV_VAR_STRING="SYNAPSE_TOKEN_AWS_SSM_PARAMETER_NAME=/synapse/cred/$EC2_INSTANCE_ID"


# modify apache proxy config
sed -i "s/^.*<LocationMatch.*\/.*\/>.*$/<LocationMatch \/$EC2_INSTANCE_ID\/>/g" /etc/apache2/sites-available/proxy.conf
# set envirronment variable for Apache 
echo "export $SYNAPSE_ENV_VAR_STRING" >> /etc/apache2/envvars
systemctl restart apache2 

# set environment variable for R
echo $SYNAPSE_ENV_VAR_STRING >> /etc/R/Renviron.site

# there does not appear to be a need to restart RStudio server