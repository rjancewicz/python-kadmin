
function mkpasswd {
    python -c "import string, random; print ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in xrange(32))"
}

kdb5_util destroy -f

# load an updated krb5.conf with correct permissions
chown --reference=/etc/krb5.conf ./krb5.conf 
chmod --reference=/etc/krb5.conf ./krb5.conf 
cp ./krb5.conf /etc/krb5.conf
restorecon /etc/krb5.conf

MASTER_PASSWORD=`mkpasswd`

cat ./kdb_create.expect | sed -e "s#MASTER_PASSWORD#$MASTER_PASSWORD#g" > /tmp/kdb_create.expect

expect /tmp/kdb_create.expect

kadmin.local -q "ank -randkey kadmin/admin"
kadmin.local -q "ank -randkey kadmin/changepw"

service kadmin restart
service krb5kdc restart