#!/bin/bash

echo "loading schema files..."

ldapmodify -Q -H ldapi:/// -Y EXTERNAL -ac -f ./schema/core.ldif
ldapmodify -Q -H ldapi:/// -Y EXTERNAL -ac -f ./schema/cosine.ldif
ldapmodify -Q -H ldapi:/// -Y EXTERNAL -ac -f ./schema/inetorgperson.ldif
ldapmodify -Q -H ldapi:/// -Y EXTERNAL -ac -f ./schema/nis.ldif
ldapmodify -Q -H ldapi:/// -Y EXTERNAL -ac -f ./schema/eduorg.ldif
ldapmodify -Q -H ldapi:/// -Y EXTERNAL -ac -f ./schema/eduperson.ldif
ldapmodify -Q -H ldapi:/// -Y EXTERNAL -ac -f ./schema/kerberos.ldif
ldapmodify -Q -H ldapi:/// -Y EXTERNAL -ac -f ./schema/misc.ldif
ldapmodify -Q -H ldapi:/// -Y EXTERNAL -ac -f ./schema/samba.ldif

