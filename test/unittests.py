
import time
import sys
import kadmin
import kadmin_local
import unittest
import subprocess
import logging

import os.path

try: 
    input = raw_input
except NameError: 
    pass

TEST_PRINCIPAL = "test/admin@EXAMPLE.COM"
TEST_KEYTAB    = "./test.keytab"
TEST_CCACHE    = "./krb5cc_test"
TEST_PASSWORD  = "example"

TEST_LOG       = "./unittests.log"
LOG_FORMAT     = "%(asctime)-15s %(message)s"

TEST_ACCOUNTS = ["test{0:02d}@EXAMPLE.COM".format(i) for i in range(100)]


def create_test_prinicipal():

    data = None

    if not os.path.isfile(TEST_KEYTAB):

        command = '''
spawn kadmin.local -p root@EXAMPLE.COM

expect "kadmin.local:" {{ send "ank {0}\r" }}
expect "Enter password for principal" {{ send "{1}\r" }}
expect "Re-enter password for principal" {{ send "{1}\r" }}

expect "kadmin.local:" {{ send "cpw {0}\r" }}
expect "Enter password for principal" {{ send "{1}\r" }}
expect "Re-enter password for principal" {{ send "{1}\r" }}

expect "kadmin.local:" {{ send "ktadd -kt {2} -norandkey {0}\r"}}
expect "kadmin.local:" {{ exit 1 }}
'''.format(TEST_PRINCIPAL, TEST_PASSWORD, TEST_KEYTAB)

        expect = subprocess.Popen(['expect'], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        expect.communicate(command.encode())
        expect.wait()


def create_ccache():

    cmd = "kinit -S kadmin/admin -c {0} -kt {1} -p {2}".format(TEST_CCACHE, TEST_KEYTAB, TEST_PRINCIPAL);
    kinit = subprocess.Popen(cmd.split(' '), shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    kinit.wait()


def create_test_accounts():

    kadmin_local = subprocess.Popen(['kadmin.local'], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    command = u''

    for account in TEST_ACCOUNTS:
        command += u'ank -randkey {0}\n'.format(account)

    kadmin_local.communicate(command.encode())
    kadmin_local.wait()

def delete_test_accounts():
    
    kadmin_local = subprocess.Popen(['kadmin.local'], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    command = u''

    for account in TEST_ACCOUNTS:
        command += u'delprinc -force {0}\n'.format(account)

    kadmin_local.communicate(command.encode())
    kadmin_local.wait()

def database_size():

    kadmin_local = subprocess.Popen(['kadmin.local'], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (stdoutdata, stderrdata) = kadmin_local.communicate(u'listprincs\n'.encode())

    kadmin_local.wait()

    # We subtract two because the pipe contains the following in addition to the principals
    #
    # kadmin.local:  listprincs
    # kadmin.local: 
    #

    return stdoutdata.decode().count('\n') - 2


class KAdminUnitTests(unittest.TestCase):
 
    ''' Missing in 2.6 '''
    def assertIsNotNone(self, expr, msg=None):
        self.assertFalse((expr is None), msg)
    
    def assertIsNone(self, expr, msg=None):
        self.assertTrue((expr is None), msg)

    
    def setUp(self):
    
        # let the exception bubble up the test.
        kadm = kadmin.init_with_keytab(TEST_PRINCIPAL, TEST_KEYTAB);
        
        if kadm is None:
            self.stop()
      
        self.kadm = kadm

        self.logger = logging.getLogger('python-kadmin')
    
    def test_init_with_keytab(self):
        
        try:    
            kadm = kadmin.init_with_keytab(TEST_PRINCIPAL, TEST_KEYTAB);
        except kadmin.KAdminError as error: 
            self.fail("kadmin.init_with_keytab failed")
     
        self.assertIsNotNone(kadm, "kadmin handle is None")

    def test_init_with_ccache(self):
        
        try:    
            kadm = kadmin.init_with_ccache(TEST_PRINCIPAL, TEST_CCACHE);
        except kadmin.KAdminError as error: 
            self.fail("kadmin.init_with_ccache failed")
     
        self.assertIsNotNone(kadm, "kadmin handle is None")

    def test_init_with_ccache_no_name(self):
        
        try:    
            kadm = kadmin.init_with_ccache(None, TEST_CCACHE);
        except kadmin.KAdminError as error: 
            self.fail("kadmin.init_with_ccache failed")
     
        self.assertIsNotNone(kadm, "kadmin handle is None")

    def test_init_with_password(self):

        try:    
            kadm = kadmin.init_with_password(TEST_PRINCIPAL, TEST_PASSWORD);
        except kadmin.KAdminError as error: 
            self.fail("kadmin.init_with_password failed")
     
        self.assertIsNotNone(kadm, "kadmin handle is None")
    
    def test_create(self):
       
        kadm = self.kadm

        delete_test_accounts()
    
        pre_size = database_size()

        try: 
            for account in TEST_ACCOUNTS:
                kadm.ank(account)
        except:
            self.fail("kadmin.ank rasied an error creating an account.") 

        post_size = database_size()

        self.assertEqual(pre_size + len(TEST_ACCOUNTS), post_size)

        delete_test_accounts()

    def test_delete(self):
        
        kadm = self.kadm

        create_test_accounts()
        
        pre_size = database_size()

        try: 
            for account in TEST_ACCOUNTS:
                kadm.delprinc(account)
        except:
            self.fail("kadmin.ank rasied an error deleting an account.") 

        post_size = database_size()
    
        self.assertEqual(pre_size, len(TEST_ACCOUNTS) + post_size)

        delete_test_accounts()


    def test_double_create(self):
        
        kadm = self.kadm
   
        delete_test_accounts()
        
        account = TEST_ACCOUNTS[0]

        kadm.ank(account)

        self.assertRaises(kadmin.KAdminError, kadm.ank, account)

    def test_double_delete(self):
        
        kadm = self.kadm
        
        delete_test_accounts()

        account = TEST_ACCOUNTS[0]

        self.assertRaises(kadmin.KAdminError, kadm.delprinc, account)
    
    def test_iteration(self):

        kadm = self.kadm
        count = 0 
        size = database_size() 

        for princ in kadm.principals():
            count += 1
      
        self.assertEqual(count, size)

    
    def test_not_exists(self):
        
        kadm = self.kadm
    
        delete_test_accounts()

        account = TEST_ACCOUNTS[0]

        princ = kadm.getprinc(account)

        self.assertIsNone(princ)


    def test_princ_compare_eq(self):

        kadm = self.kadm

        create_test_accounts()

        account = TEST_ACCOUNTS[0]

        a = kadm.getprinc(account)
        b = kadm.getprinc(account)

        self.assertEqual(a, b)
    

    def test_princ_compare_ne(self):

        kadm = self.kadm

        create_test_accounts()

        account = TEST_ACCOUNTS[0]

        a = kadm.getprinc(account)

        account = TEST_ACCOUNTS[1]

        b = kadm.getprinc(account)

        self.assertNotEqual(a, b)
    


class KAdminLocalUnitTests(unittest.TestCase):
#class KAdminLocalUnitTests():

    ''' Missing in 2.6 '''
    def assertIsNotNone(self, expr, msg=None):
        self.assertFalse((expr is None), msg)
    
    def assertIsNone(self, expr, msg=None):
        self.assertTrue((expr is None), msg)

    
    def setUp(self):
    
        # let the exception bubble up the test.
        kadm = kadmin_local.local();
        
        if kadm is None:
            self.stop()
      
        self.kadm = kadm

        self.logger = logging.getLogger('python-kadmin')
    
    
    def test_local(self):
        
        try:    
            kadm = kadmin_local.local();
        except kadmin_local.KAdminError as error: 
            self.fail("kadmin_local.init_with_keytab failed");
     
        self.assertIsNotNone(kadm, "kadmin_local handle is None")
       
    def test_init_with_keytab(self):
        
        try:    
            kadm = kadmin_local.init_with_keytab(TEST_PRINCIPAL, TEST_KEYTAB);
        except kadmin_local.KAdminError as error: 
            self.fail("kadmin.init_with_keytab failed")
     
        self.assertIsNotNone(kadm, "kadmin handle is None")

    def test_init_with_ccache(self):
        
        try:    
            kadm = kadmin_local.init_with_ccache(TEST_PRINCIPAL, TEST_CCACHE);
        except kadmin_local.KAdminError as error: 
            self.fail("kadmin.init_with_ccache failed")
     
        self.assertIsNotNone(kadm, "kadmin handle is None")

    def test_init_with_ccache_no_name(self):
        
        try:    
            kadm = kadmin_local.init_with_ccache(None, TEST_CCACHE);
        except kadmin_local.KAdminError as error: 
            self.fail("kadmin.init_with_ccache failed")
     
        self.assertIsNotNone(kadm, "kadmin handle is None")

    def test_init_with_password(self):
        
        try:    
            kadm = kadmin_local.init_with_password(TEST_PRINCIPAL, TEST_PASSWORD);
        except kadmin_local.KAdminError as error: 
            self.fail("kadmin.init_with_password failed")
     
        self.assertIsNotNone(kadm, "kadmin handle is None")

    
    def test_create(self):
       
        kadm = self.kadm

        delete_test_accounts()
    
        pre_size = database_size()

        try: 
            for account in TEST_ACCOUNTS:
                kadm.ank(account)
        except:
            self.fail("kadmin_local.ank rasied an error creating an account.") 

        post_size = database_size()

        self.assertEqual(pre_size + len(TEST_ACCOUNTS), post_size)

        delete_test_accounts()

    def test_delete(self):
        
        kadm = self.kadm

        create_test_accounts()
        
        pre_size = database_size()

        try: 
            for account in TEST_ACCOUNTS:
                kadm.delprinc(account)
        except:
            self.fail("kadmin_local.ank rasied an error deleting an account.") 

        post_size = database_size()
    
        self.assertEqual(pre_size, len(TEST_ACCOUNTS) + post_size)

        delete_test_accounts()


    def test_double_create(self):
        
        kadm = self.kadm
   
        delete_test_accounts()
        
        account = TEST_ACCOUNTS[0]

        kadm.ank(account)

        self.assertRaises(kadmin_local.KAdminError, kadm.ank, account)

    def test_double_delete(self):
        
        kadm = self.kadm
        
        delete_test_accounts()

        account = TEST_ACCOUNTS[0]

        self.assertRaises(kadmin_local.KAdminError, kadm.delprinc, account)

    def test_iteration(self):

        kadm = self.kadm
        count = 0 
        size = database_size() 

        for princ in kadm.principals():
            count += 1
      
        self.assertEqual(count, size)

    def test_each_iteration(self):

        kadm = self.kadm
        count = [0]

        delta = 0

        size = database_size()

        start = time.time()

        def fxn(princ, data):
            data[0] += 1

        kadm.each_principal(fxn, count)

        end = time.time()

        delta = end - start

        self.logger.info("each iteration {0} principals in {1} seconds. [{2} principals/second]".format(count[0], delta, (count[0]/delta)))

        self.assertEqual(count[0], size)

    def test_not_exists(self):
        
        kadm = self.kadm
    
        delete_test_accounts()

        account = TEST_ACCOUNTS[0]

        princ = kadm.getprinc(account)

        self.assertIsNone(princ)

    
    def test_princ_compare_eq(self):

        kadm = self.kadm

        create_test_accounts()

        account = TEST_ACCOUNTS[0]

        a = kadm.getprinc(account)
        b = kadm.getprinc(account)

        self.assertEqual(a, b)
    

    def test_princ_compare_ne(self):

        kadm = self.kadm

        create_test_accounts()

        account = TEST_ACCOUNTS[0]

        a = kadm.getprinc(account)

        account = TEST_ACCOUNTS[1]

        b = kadm.getprinc(account)

        self.assertNotEqual(a, b)



def main():
    
    confirm = input('run tests against local kadmin server [yes/no] ? ')

    if confirm.lower() == 'yes':

        create_test_prinicipal()
        create_ccache()

        logging.basicConfig(filename=TEST_LOG, format=LOG_FORMAT, level=logging.DEBUG)

        unittest.main()

if __name__ == '__main__':
    main()


