## (c) 2018 integrate.ai
## Helper module for use in EMR bootstrap actions and in 
## Corporate Realm machines that require keytabs
##
## Assumes SSM parameters in region like:
##
##  <customer_identifier>-realm-name
##  <customer_indentifier>-realm-principal
##  <customer_identifier>-realm-principal-creds
##
##  see github.com/deployment/terraform/emr/<customer_identifier>/ssm.tf
##
##  If no customer identifier is passed, assumes:
##  
##  corp-iai-realm-name
##  corp-iai-realm-principal
##  corp-iai-realm-principal-creds
##
##  Machine EC2 role must have access to decryption key
##  for these SSM Parameters in order to execute this 
##  script successful. These keys are assumed, not checked
##  for.
##  
##  see github.com/deployment/terraform/network/auth_services.tf
##
## Only one public method:
##      create_host_principal_keytab( customer, keytabfilename )

import logging
import boto3
import kadmin
import socket


## Creates or gets the Host Principal and then makes a new
## keytab file using the keytabfilename parameter
## throws an exception if the keytabfilename exists and 
## contains an existing keytab
def create_host_principal_keytab( customer, keytabfilename ):
    return create_service_principal_keytab( customer, "host", keytabfilename)

def create_service_principal_keytab( customer, service, keytabfilename ):
    
    result = False
    realm = _get_realm_name( customer )
    admin_principal_name = _get_realm_admin_princ_name(customer)
    admin_cred = _get_realm_admin_princ_cred(customer)

    kadm_sess = _get_kadm_session (admin_principal_name, admin_cred)
    
    srv_princ_name = _get_principal_name(realm, service)

    if not _principal_exists(kadm_sess, srv_princ_name):
        _create_principal(kadm_sess, srv_princ_name)
    
    srv_principal = _get_principal(kadm_sess, srv_princ_name)
    
    if srv_principal is not None:
        result = _kadmin_ktadd(kadm_sess, srv_principal.principal, keytabfilename )
        
    logging.info("keytab file %s created", keytabfilename)
    
    return result;


### get param values from SSM
def _get_ssm_param_value ( param_name, decrypt_flag ):
    ssmClient = boto3.client("ssm")
    response = ssmClient.get_parameter(Name = param_name, WithDecryption = decrypt_flag );
    
    return  response["Parameter"]["Value"]

## use socket.getfqdn to build host principal name
def _get_principal_name(realm, prefix = None):
    if prefix is None:
        prefix = "host";

    host_fqdn = socket.getfqdn()
    return prefix + "/" + host_fqdn + "@" + realm

## get kadm session
def _get_kadm_session( user_name, user_cred ):
    return kadmin.init_with_password(user_name, user_cred)

## get realm from SSM key prefixed by iai_realm_name
def _get_realm_name( customer = None ):
    if customer is None:
        customer = "corp-iai"

    sparam = customer + "-realm-name"

    return _get_ssm_param_value( sparam, True )

## get realm admin name from SSM key prefixed by iai_realm_amdin_principal_ 
## This does not need to be full admin - but should be able to create
## principals, look up principals and export keys (so nearly a full admin)
def _get_realm_admin_princ_name( customer = None ):
    if customer is None:
        customer = "corp-iai"

    sparam = customer + "-realm-principal"

    return _get_ssm_param_value( sparam, True )

## get realm admin credential value - this is a password for now
## but it could be a base64 keytab in the future
def _get_realm_admin_princ_cred( customer = None ):
    if customer is None:
        customer = "corp-iai"

    sparam = customer + "-realm-principal-creds"

    return _get_ssm_param_value( sparam, True )

## Returns the specifically named principal
def _get_principal ( kadm_sess, principal_name ):
    if kadm_sess is not None:
        principal = kadm_sess.getprinc(principal_name)
        return principal
    else:
        return None #TODO: Throw here!

## Checks if the principal exists
def _principal_exists( kadm_sess, principal_name ):
    exists = False
    if kadm_sess is not None:
        exists = kadm_sess.principal_exists(principal_name)
    
    return exists

## Creates principal - throws DuplicateError if principal exists
def _create_principal( kadm_sess, princ_name ):
    created = False
    if kadm_sess is not None:
        try:
            created = kadm_sess.add_principal(princ_name, None)
        except kadmin.DuplicateError:
            created = True
    
    return created

## Creates Keytab file - uses enhanced python-kadmin library
## github.com/integrateai/python-kadmin
##    forked from rjancewicz/python-kadmin 
##    and enhanced with very based ktadd functionality
##
def _kadmin_ktadd( kadm_sess, princ_name, ktname ):
    created = False
    if kadm_sess is not None:
        created = kadm_sess.ktadd(princ_name, ktname) 

    return created
