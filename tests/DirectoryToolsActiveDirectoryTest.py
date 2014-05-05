#!/usr/bin/python

import DirectoryTools
import DirectoryToolsIndexes as indexes
from DirectoryToolsTestsCommon import DirectoryToolsTestsCommon as common
import unittest

'''
README

Before running this test, you will need to set up your LDAP server in the same way that I have.
This test was done using a Windows Server 2008 domain controller, though it should by design also work on a Samba 4 domain.

Users UIDs:
- alan
- bob
- carl
- dave

Groups:
- Local Administrators
    Description: Privileged users.
    Members: alan
- Employees
    Description: Basic Users
    Members: 'Local Administrators' group, bob
- Wiki Access
    Description: Represents a service on the network. All employees are assumed to be trusted, but some guests will need access too.
    Members: 'Employees' group, carl
- Local Guests
    Members: carl, dave
'''

class DirectoryToolsFreeIPATest(common,unittest.TestCase):
    
    def setUp(self):
        
        print '\nSetting up for: {0}'.format(self.id())
        
        properties = {
            indexes.BASE_DN:'dc=sandbox,dc=lan',
            indexes.SERVER_ADDRESS:'sandbox.lan',
            indexes.SERVER_PORT:'3268',
            indexes.USE_SSL:False,
            indexes.PROXY_USER:'CN=Administrator,CN=Users,DC=sandbox,DC=lan',
            indexes.PROXY_PASSWORD:'administratorPassword',
            indexes.DEBUG_LEVEL:0
        }

        self.auth = DirectoryTools.DirectoryTools(properties,'ad')
    
        # Defining group values.
        self.adminGroup = 'Local Administrators'
        self.employeeGroup = 'Employees'
        self.guestGroup = 'Local Guests'
        self.serviceGroup = 'Wiki Access'
        # Counts of the intended number of direct/indirect members in a group used in a unit test.
        self.serviceGroupDirectUserMemberCount = 1
        self.serviceGroupNestedUserMemberCount = 3
    
        self.userA = 'alan'
        self.userB = 'bob'
        self.userC = 'carl'
        self.userD = 'dave'
        
        # All users have the same password in my test environment.
        self.userPassword = 'Password123$'
        
if __name__ == '__main__':
    unittest.main()
