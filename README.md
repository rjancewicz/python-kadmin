python-kadmin
=============

Python module for kerberos admin (kadm5)

Examples:
  Change a password: 

>  import kadmin
>
>  kadm = kadmin.init_with_keytab("user@EXAMPLE.COM", "/path/to/file.keytab")

>  princ = kadm.get_princ("user@EXAMPLE.COM")

>  princ.change_password("correcthorsebatterystaple")

  List accounts:

> import kadmin
>
> kadm = kadmin.init_with_keytab("user@EXAMPLE.COM", "/path/to/file.keytab")

> for princ in kadm.principals():

>   print princ
