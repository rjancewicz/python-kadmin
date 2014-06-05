
import kadmin

admin = kadmin.init_with_keytab("test/admin", "./test.keytab")

iter = admin.principals(match="[a-z][a-z][a-z][a-z]@EXAMPLE.COM")

for princ in iter:
    try:
        admin.delprinc(princ)
    except kadmin.KAdminError as error:
        print(error)
        
