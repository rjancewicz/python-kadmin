python-kadmin
=============

Python module for kerberos admin (kadm5)

## Initilization

### kadmin
```python
import kadmin

kadm = kadmin.init_with_keytab("user/admin@EXAMPLE.COM", "/path/to/keytab")
kadm = kadmin.init_with_ccache("user/admin@EXAMPLE.COM", "/path/to/krb5cc")
kadm = kadmin.init_with_password("user/admin@EXAMPLE.COM", "aStrongPassword")
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

###Principal Creation: 

```python
>>> 
>>> # ank, addprinc, add_principal are all aliases for principal creation
>>> # omitting a password or setting to None results in a randomized key
>>> # kadm.ank(principal [, password|None] [, db_args=db_args])
>>> 
>>> kadm.ank("user@EXAMPLE.COM", "correcthorsebatterysaple")
>>> kadm.addprinc("user@EXAMPLE.COM", None)
>>> # 
>>> kadm.add_principal("user@EXAMPLE.COM", None, db_args={'dn':'uid=user,ou=people,dc=example,dc=com'})
>>>
```

###Principal Attributes:
```python
>>> princ = kadm.getprinc("user@EXAMPLE.COM")
>>>
>>> # getters only
>>> princ.principal
>>> # get: unicode
>>>
>>> princ.name
>>> # get: unicode
>>>
>>> princ.mod_name
>>> # get: unicode
>>>
>>> princ.mod_date
>>> # get: datetime.datetime
>>>
>>> princ.last_pwd_change
>>> # get: [datetime.datetime|None]
>>>
>>> princ.last_success
>>> # get: [datetime.datetime|None]
>>>
>>> princ.last_failure
>>> # get: [datetime.datetime|None]
>>>
>>>
>>> #getters & setters
>>> princ.expire = datetime.datetime(2014, 12, 25)
>>> # get: datetime.datetime
>>> # set: [str|unicode|datetime.datetime|None]
>>>
>>> princ.pwexpire = u'Now'
>>> # get: datetime.datetime
>>> # set: [str|unicode|datetime.datetime|None]
>>>
>>> princ.maxlife = "8 Days"
>>> # get: datetime.timedelta
>>> # set: [str|unicode|datetime.timedelta|None]
>>>
>>> princ.maxrenewlife = datetime.timedelta(days=2)
>>> # get: datetime.timedelta
>>> # set: [str|unicode|datetime.timedelta|None]
>>>
>>> princ.policy = "strong_password_policy"
>>> # get: unicode
>>> # set: [str|unicode|kadmin.Policy]
>>>
>>> princ.kvno = 1
>>> # get: int
>>> # set: [int]
>>>
>>> # at this point the local copy of the principal is modified
>>> #  the remote will not change until commit is called as shown
>>> princ.commit()
>>>
>>> # for an existing principal object discard local state and
>>> #  fetch the state as it appears in the database
>>> princ.reload()



```

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
	print("{0}{1}".format(data, princ))

# invoke callback_a for each principal, equivilent of the above iteration.
kadm.each_principal(callback_a)

# invoke callback_b for each principal resulting in "Hello, principal@EXAMPLE.COM"
kadm.each_principal(callback_b, data="Hello, ")

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
