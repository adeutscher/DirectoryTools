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
    '''
    Unit tests for testing against a FreeIPA server.
    '''
    def setUp(self):
        '''
        Prepare DirectoryTools for testing against a FreeIPA server.
        '''
        
        print '\nSetting up for: {0}'.format(self.id())
        
        ## Properties for my test FreeIPA domain.
        properties = {
            indexes.BASE_DN:'dc=freeipa,dc=lan',
            indexes.SERVER_ADDRESS:'centos-1.freeipa.lan',
            indexes.SERVER_PORT:'389',
            indexes.USE_SSL:False,
            indexes.PROXY_USER:'uid=admin,cn=users,cn=accounts,dc=freeipa,dc=lan',
            indexes.PROXY_PASSWORD:'MyAdminPassword1!',
            indexes.LOG_LEVEL:DirectoryTools.LOG_LEVEL_CRITICAL,
            #indexes.PROXY_IS_ANONYMOUS:True,
        }

        ## DirectoryTools object to run tests with.
        self.auth = DirectoryTools.DirectoryTools(properties,'freeipa',enableStdOut=True)
    
        # Defining group values.
        ## Name of the administrator group.
        self.adminGroup = 'localadmins'
        ## Name of the employee group.
        self.employeeGroup = 'employees'
        ## Name of the guest group.
        self.guestGroup = 'guests'
        ## Name of service access group.
        self.serviceGroup = 'wiki-access'
        
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
        self.userPassword = 'UserPassword1!'
        
        ## Target attribute for the getMultiAttribute test.
        self.targetAttribute = 'email'
        ## Target attributes for the getMultiAttributes test.
        self.targetAttributes = ['objectClass','cn']
        
if __name__ == '__main__':
    unittest.main()
