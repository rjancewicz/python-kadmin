python-kadmin
=============

Python module for kerberos admin (kadm5)

## Initilization

### kadmin
```python
import kadmin

kadm = kadmin.init_with_keytab("user/admin@EXAMPLE.COM", "/path/to/keytab")
kadm = kadmin.init_with_ccache("user/admin@EXAMPLE.COM", "/path/to/krb5cc")
kadm = kadmin.init_wiht_password("user/admin@EXAMPLE.COM", "aStrongPassword")
```
### kadmin_local
used for direct database access as local root account.
```python
import kadmin_local as kadmin

kadm = kadmin.local();
```
\* kadmin\_local also supports the other init\_with\_&lt;method&gt; initializers whereas kadmin does not support local.
It is advised that kadmin_local is used for rapid unpacked iteration, other tasks should be handled by the gssapi connection.


##Examples:
###Change a password:
```python
princ = kadm.get_princ("user@EXAMPLE.COM")
princ.change_password("correcthorsebatterystaple")
```

###Iteration:
```python
for princ in kadm.principals():
  # princ is a string
  print princ

for princ in kadm.principals('r*@EXAMPLE.COM'):
  # princ is a string starting with 'r' and ending with '@EXAMPLE.COM'
  print princ

for princ in kadm.principals('*', unpack=True):
  # princ is a kadmin principal object
  print princ
```
