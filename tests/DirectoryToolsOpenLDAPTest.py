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
    
    def setUp(self):
        
        print '\nSetting up for: {0}'.format(self.id())
        
        properties = {
            indexes.BASE_DN:'dc=openldap,dc=lan',
            indexes.SERVER_ADDRESS:'10.10.9.12',
            indexes.SERVER_PORT:'389',
            indexes.USE_SSL:False,
            indexes.PROXY_USER:'cn=admin,dc=openldap,dc=lan',
            indexes.PROXY_PASSWORD:'MyAdminPassword1!',
            indexes.DEBUG_LEVEL:3
        }

        self.auth = DirectoryTools.DirectoryTools(properties,'openldap')
    
        # Defining group values.
        self.adminGroup = 'admins'
        self.employeeGroup = 'employees'
        self.guestGroup = 'guests'
        self.serviceGroup = 'wiki-access'
        # Counts of the intended number of direct/indirect members in a group used in a unit test.
        self.serviceGroupDirectUserMemberCount = 3
    
        self.userA = 'alan'
        self.userB = 'bob'
        self.userC = 'carl'
        self.userD = 'dave'
        
        # All users have the same password in my test environment.
        self.userPassword = 'UserPassword1!'
        
        # Target attribute for the getMultiAttribute test.
        self.targetAttribute = 'email'
        # Target attributes for the getMultiAttributes test.
        self.targetAttributes = ['objectClass','cn']
        
    @unittest.skip('OpenLDAP Server is not set up for nested groups')
    def test_getNestedGroupMembers(self):
        self.assertTrue(True)
        
if __name__ == '__main__':
    
    unittest.main()
