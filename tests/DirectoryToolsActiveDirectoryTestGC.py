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

class DirectoryToolsActiveDirectoryTestGC(common,unittest.TestCase):
    '''
    Unit tests for Global Catalog (Windows Server 2008).
    '''
    
    def setUp(self):
        '''
        Prepare DirectoryTools for testing against Global Catalog on an Active Directory server (Windows Server 2008).
        '''
        
        print '\nSetting up for: {0}'.format(self.id())
        
        ## Properties for my test domain.
        properties = {
            indexes.BASE_DN:'dc=sandbox,dc=lan',
            indexes.SERVER_ADDRESS:'sandbox.lan',
            indexes.SERVER_PORT:'3268',
            indexes.USE_SSL:False,
            indexes.PROXY_USER:'CN=Administrator,CN=Users,DC=sandbox,DC=lan',
            indexes.PROXY_PASSWORD:'MyAdminPassword1!',
            indexes.LOG_LEVEL:DirectoryTools.LOG_LEVEL_CRITICAL,
        }

        ## DirectoryTools object to test with.
        self.auth = DirectoryTools.DirectoryTools(properties,'ad',enableStdOut=True)
    
        # Defining group values.
        
        ## Name of the administrator group.
        self.adminGroup = 'Local Administrators'
        ## Name of the employee group.
        self.employeeGroup = 'Employees'
        ## Name of the guest group.
        self.guestGroup = 'Local Guests'
        ## Name of the service access group.
        self.serviceGroup = 'Wiki Access'
        
        # Counts of the intended number of direct/indirect members in a group used in a unit test.
        ## Intended number of direct users.
        self.serviceGroupDirectUserMemberCount = 1
        ## Intended number of direct and indirect users.
        self.serviceGroupNestedUserMemberCount = 3
    
        ## Name of user A.
        self.userA = 'alan'
        ## Name of user B.
        self.userB = 'bob'
        ## Name of user C.
        self.userC = 'carl'
        ## Name of user D.
        self.userD = 'dave'
        
        ## User password. All users have the same password in my test environment.
        self.userPassword = 'MyUserPassword1!'
        
        ## Target attribute for the getMultiAttribute test.
        self.targetAttribute = 'email'
        ## Target attributes for the getMultiAttributes test.
        self.targetAttributes = ['objectClass','cn']
        
if __name__ == '__main__':
    unittest.main()
