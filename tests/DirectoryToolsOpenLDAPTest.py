#!/usr/bin/python

import DirectoryTools
import DirectoryToolsIndexes as indexes
from DirectoryToolsTestsCommon import DirectoryToolsTestsCommon as common
import unittest

'''
README

Before running this test, you will need to set up your LDAP server in the same way that I have.
This test was done using a fresh setup of an.

Users UIDs:
- alan
- bob
- carl
- dave

Groups:
- admins
    Description: Privileged users.
    Members: alan
- employees
    Description: Basic Users
    Members: alan, bob
- wiki-access
    Description: Represents a service on the network.
    Members: alan, bob, carl
- guests
    Members: carl, dave
'''

class DirectoryToolsOpenLDAPTest(common,unittest.TestCase):
    '''
    Unit tests for testing against a fresh OpenLDAP server.
    '''
    def setUp(self):
        '''
        Prepare DirectoryTools for testing against a fresh OpenLDAP server.
        '''
        
        print '\nSetting up for: {0}'.format(self.id())
        
        ## Properties for my test domain.
        properties = {
            indexes.BASE_DN:'dc=openldap,dc=lan',
            indexes.SERVER_ADDRESS:'10.10.9.12',
            indexes.SERVER_PORT:'389',
            indexes.USE_SSL:False,
            indexes.PROXY_USER:'cn=admin,dc=openldap,dc=lan',
            indexes.PROXY_PASSWORD:'MyAdminPassword1!',
            indexes.DEBUG_LEVEL:3
        }

        ## DirectoryTools object to run tests with.
        self.auth = DirectoryTools.DirectoryTools(properties,'openldap')
    
        # Defining group values.
        ## Name of the administrator group.
        self.adminGroup = 'admins'
        ## Name of the employee group.
        self.employeeGroup = 'employees'
        ## Name of the guest group.
        self.guestGroup = 'guests'
        ## Name of the service access group.
        self.serviceGroup = 'wiki-access'
        
        ## The expected number of direct members that are expected to be in the service group.
        self.serviceGroupDirectUserMemberCount = 3
    
        ## Name of user A.
        self.userA = 'alan'
        ## Name of user B.
        self.userB = 'bob'
        ## Name of user C.
        self.userC = 'carl'
        ## Name of user D.
        self.userD = 'dave'
        
        ## User password. All users have the same password in my test environment.
        self.userPassword = 'UserPassword1!'
        
        ## Target attribute for the getMultiAttribute test.
        self.targetAttribute = 'email'
        ## Target attributes for the getMultiAttributes test.
        self.targetAttributes = ['objectClass','cn']
        
    @unittest.skip('OpenLDAP Server is not set up for nested groups')
    def test_getNestedGroupMembers(self):
        '''
        Dummy test. My OpenLDAP server is not set up with nested groups.
        '''
        self.assertTrue(True)
        
if __name__ == '__main__':
    
    unittest.main()
