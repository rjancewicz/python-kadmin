python-kadmin
=============

Python module for kerberos admin (kadm5)

sample usage:

>  import kadmin

>  k = kadmin.init_with_keytab("user@DOMAIN", "/path/to/file.keytab")

>  p = k.get_princ("user@DOMAIN")

>  p.change_password("correcthorsebatterystaple")

