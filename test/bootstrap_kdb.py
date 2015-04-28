
import kadmin

admin = kadmin.init_with_keytab("test/admin", "./test.keytab")

for a in xrange(97, 98):
    print(chr(a))
    for b in xrange(97, 123):
        for c in xrange(97, 123):
            for d in xrange(97, 123):
                try:
                    admin.ank(chr(a) + chr(b) + chr(c) + chr(d));
                except kadmin.KAdminError as error:
                    print error
                    pass
