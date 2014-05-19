#!/usr/bin/python

import DirectoryTools
import DirectoryToolsIndexes as indexes
from DirectoryToolsTestsCommon import DirectoryToolsTestsCommon as common
import unittest

'''
README

Before running this test, you will need to set up your LDAP server in the same way that I have.
This test was done using a fresh setup of a FreeIPA domain.

Users UIDs:
- alan
- bob
- carl
- dave

Groups:
- localadmins
    Description: Privileged users.
    Members: alan
- Employees
    Description: Basic Users
    Members: 'localadmins' group, bob
- wiki-access
    Description: Represents a service on the network. All employees are assumed to be trusted, but some guests will need access too.
    Members: 'Employees' group, carl
- guests
    Members: carl, dave
'''

class DirectoryToolsFreeIPATest(common,unittest.TestCase):
    
    def setUp(self):
        
        print '\nSetting up for: {0}'.format(self.id())
        
        properties = {
            indexes.BASE_DN:'dc=freeipa,dc=lan',
            indexes.SERVER_ADDRESS:'centos-1.freeipa.lan',
            indexes.SERVER_PORT:'389',
            indexes.USE_SSL:False,
            indexes.PROXY_USER:'uid=admin,cn=users,cn=accounts,dc=freeipa,dc=lan',
            indexes.PROXY_PASSWORD:'MyAdminPassword1!',
            indexes.DEBUG_LEVEL:3,
            #indexes.PROXY_IS_ANONYMOUS:True,
        }

        self.auth = DirectoryTools.DirectoryTools(properties,'freeipa')
    
        # Defining group values.
        self.adminGroup = 'localadmins'
        self.employeeGroup = 'employees'
        self.guestGroup = 'guests'
        self.serviceGroup = 'wiki-access'
        # Counts of the intended number of direct/indirect members in a group used in a unit test.
        self.serviceGroupDirectUserMemberCount = 1
        self.serviceGroupNestedUserMemberCount = 3
    
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
        
if __name__ == '__main__':
    unittest.main()
