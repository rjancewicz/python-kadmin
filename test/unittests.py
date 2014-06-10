
import time
import sys
import kadmin
import kadmin_local
import unittest
import subprocess
import logging

TEST_PRINCIPAL = "test/admin@EXAMPLE.COM"
TEST_KEYTAB    = "./test.keytab"
TEST_CCACHE    = "./krb5cc_test"
TEST_PASSWORD  = "example"

TEST_LOG       = "./unittests.log"
LOG_FORMAT     = "%(asctime)-15s %(message)s"

TEST_ACCOUNTS = ["test{0:02d}@EXAMPLE.COM".format(i) for i in range(100)]

def create_ccache():

    cmd = "kinit -S kadmin/admin -c {0} -kt {1} -p {2}".format(TEST_CCACHE, TEST_KEYTAB, TEST_PRINCIPAL);
    kinit = subprocess.Popen(cmd.split(' '), shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    kinit.wait()


def create_test_accounts():

    kadmin_local = subprocess.Popen(['kadmin.local'], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    command = ""

    for account in TEST_ACCOUNTS:
        command += 'ank -randkey {0}\n'.format(account)

    kadmin_local.communicate(command)
    kadmin_local.wait()

def delete_test_accounts():
    
    kadmin_local = subprocess.Popen(['kadmin.local'], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    command = ""

    for account in TEST_ACCOUNTS:
        command += 'delprinc -force {0}\n'.format(account)

    kadmin_local.communicate(command)
    kadmin_local.wait()

def database_size():

    kadmin_local = subprocess.Popen(['kadmin.local'], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (stdoutdata, stderrdata) = kadmin_local.communicate('listprincs\n')

    kadmin_local.wait()

    # We subtract two because the pipe contains the following in addition to the principals
    #
    # kadmin.local:  listprincs
    # kadmin.local: 
    #

    return stdoutdata.count('\n') - 2


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

    '''
    unpack iteration is SLOW over GSSAPI connections, while still enabled it is advised that this is only used via kadmin.local
    def test_unpack_iteration(self):

        kadm = self.kadm
        count = 0
   
        size = database_size()     

        for princ in kadm.principals(unpack=True):
            count += 1
        
        self.assertEqual(count, size)
    '''

    def test_filter_iteration(self):

        kadm = self.kadm
        count = 0
        
        size = len(TEST_ACCOUNTS)

        create_test_accounts()

        for princ in kadm.principals('test[0-9][0-9]', unpack=True):
            count += 1
        
        self.assertEqual(count, size)
        
        delete_test_accounts()
        
    def test_not_exists(self):
        
        kadm = self.kadm
    
        delete_test_accounts()

        account = TEST_ACCOUNTS[0]

        princ = kadm.getprinc(account)

        self.assertIsNone(princ)

class KAdminLocalUnitTests(unittest.TestCase):
 
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
    
    def test_unpack_iteration(self):

        kadm = self.kadm
        count = 0
   
        size = database_size()     

        time_s = time.time()

        for princ in kadm.principals(unpack=True):
            count += 1

        time_f = time.time()

        time_d = time_f - time_s; 

        logging.info("unpacked iteration: {0} principals unpacked in {1} seconds [{2} per second].".format(count, time_d, (count/time_d)))
        
        self.assertEqual(count, size)
    
    def test_filter_iteration(self):

        kadm = self.kadm
        count = 0
        
        size = len(TEST_ACCOUNTS)

        create_test_accounts()

        for princ in kadm.principals('test[0-9][0-9]', unpack=True):
            count += 1
        
        self.assertEqual(count, size)
        
        delete_test_accounts()
        
    def test_not_exists(self):
        
        kadm = self.kadm
    
        delete_test_accounts()

        account = TEST_ACCOUNTS[0]

        princ = kadm.getprinc(account)

        self.assertIsNone(princ)


def main():
    
    confirm = raw_input('run tests against local kadmin server [yes/no] ? ')

    if confirm.lower() == 'yes':
        create_ccache()

        logging.basicConfig(filename=TEST_LOG, format=LOG_FORMAT, level=logging.DEBUG)

        unittest.main()

if __name__ == '__main__':
    main()


