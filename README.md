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

# unpacked iteration
#  prints each principal, data is optiona

def callback_a(princ, data):
	print(princ)

def callback_b(princ, data):
	print("{0}, {1}".format(data, princ))

# invoke callback_a for each principal, equivilent of the above iteration.
kadm.each_principal(callback_a)

# invoke callback_b for each principal resulting in "Hello, principal@EXAMPLE.COM"
kadm.each_principal(callback_b, "Hello ")

#
# WARNING: unpack iteration deprecated in favor of "each iteration" with callbacks.
#		   unless run on the default backend via kadmin_local unpack iteration is *extremely* slow.
#

# old style unpack iteration [updated]
# replaces: kadm.principals('*', unpack=True)

for princ in kadm.principals('*'):
	principal = kadm.get_princ(princ)
	# use principal as needed
	
```
