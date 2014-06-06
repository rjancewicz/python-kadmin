
import sys
import kadmin
import unittest
import subprocess

TEST_PRINCIPAL = "test/admin@EXAMPLE.COM"
TEST_KEYTAB    = "./test.keytab"

TEST_ACCOUNTS = ["test{0:02d}@EXAMPLE.COM".format(i) for i in range(100)]


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
            self.fail("kadmin.init_with_keytab failed");
     
        self.assertIsNotNone(kadm, "kadmin handle is None")

    def test_init_with_password(self):
        pass

    
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
        
    def test_unpack_iteration(self):

        kadm = self.kadm
        count = 0
   
        size = database_size()     

        for princ in kadm.principals(unpack=True):
            count += 1
        
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
        unittest.main()

if __name__ == '__main__':
    main()


