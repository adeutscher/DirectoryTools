#!/usr/bin/python

import DirectoryTools
import DirectoryToolsIndexes as indexes
import unittest

'''

Contains common methods used in testing DirectoryTools across different varieties of LDAP servers.

'''

class DirectoryToolsTestsCommon(object):

    '''
    Attempt to authenticate a user. Demonstrates a successful password and then modifies the password to create a failure.
    '''
    def test_authenticate(self):
        
        successfulAuth = self.auth.authenticate(self.userA,self.userPassword)
        self.assertTrue(successfulAuth)
        
        failedAuth = self.auth.authenticate(self.userA,self.userPassword + 'nope')
        self.assertFalse(failedAuth)
    
    '''
    Tests retrieving information on which users belong to a group.
    '''
    def test_getGroupMembers(self):
        
        # Searching the service group, which has both direct and indirect members.
        searchedGroup = self.serviceGroup
        
        # Test the ability to search through nested groups.
        
        # Search and retrieve login names, as set in initial configuration.
        nestedMemberList = self.auth.getUsersInGroup(searchedGroup)
        print 'Displaying members of {0} group: {1}'.format(searchedGroup,nestedMemberList)
        self.assertEquals(len(nestedMemberList),self.serviceGroupNestedUserMemberCount)
        
        # Search and retrieved distinguished names. A DN shall be considered valid if it is longer than the login name.
        nestedMemberDNList = self.auth.getUsersInGroup(searchedGroup,returnMembersAsDN=True)
        print 'Displaying members of {0} group: {1}'.format(searchedGroup,nestedMemberDNList)
        
        # Make sure we have the same number of results as before.
        self.assertEquals(len(nestedMemberDNList),len(nestedMemberList))
        
        for i in range(len(nestedMemberDNList)):
            self.assertTrue(len(nestedMemberDNList[i]) > len(nestedMemberList[i]))

        # Test getting group members without nesting. Direct user memberships only.
        self.auth.setProperty(indexes.NESTED_GROUPS,False)
        directMemberList = self.auth.getUsersInGroup(searchedGroup)
        print 'Displaying members of {0} group: {1}'.format(searchedGroup,directMemberList)
        self.assertEquals(len(directMemberList),self.serviceGroupDirectUserMemberCount)
        
        # Search and retrieved distinguished names. A DN shall be considered valid if it is longer than the login name.
        directMemberDNList = self.auth.getUsersInGroup(searchedGroup,returnMembersAsDN=True)
        print 'Displaying members of {0} group: {1}'.format(searchedGroup,nestedMemberDNList)
        
        # Make sure we have the same number of results as before.
        self.assertEquals(len(directMemberDNList),len(directMemberList))
        
        for i in range(len(directMemberDNList)):
            self.assertTrue(len(directMemberDNList[i]) > len(directMemberList[i]))

    '''
    Tests the retrieval of a multi-valued attribute from an object. DirectoryTools returns multi-valued objects as lists.
    '''
    def test_getMultiAttributes(self):
        
        targetAttribute = 'memberOf'
        targetDN = self.auth.resolveGroupDN(self.employeeGroup)
        
        attributeList = self.auth.getMultiAttribute(targetDN,targetAttribute)
        
        print 'Displaying values of the attribute "{0}" for the object "{1}": {2}'.format(targetAttribute,targetDN,attributeList)
        
    '''
    Test that we can detect whether or not a user is in the specified group.
    '''
    def test_isUserInGroup(self):
        
        targetGroup = self.serviceGroup
        
        targetMemberUID = self.userC
        targetNonMemberUID = self.userD
        
        # Testing with UID names, not distinguished names.
        
        isMember = self.auth.isUserInGroup(targetMemberUID,targetGroup)
        self.assertTrue(isMember)
        isNotMember = self.auth.isUserInGroup(targetNonMemberUID,targetGroup)
        self.assertFalse(isNotMember)
        
    '''
    Test the retrieval and manipulation of properties.
    '''
    def test_properties(self):
        
        # Setting this boolean property to the inverse of its previous value.
        targetProperty = indexes.NESTED_GROUPS
        oldValue = self.auth.getProperty(targetProperty)
        self.auth.setProperty(targetProperty,not bool(targetProperty))
        newValue = self.auth.getProperty(targetProperty)
        self.assertNotEquals(oldValue,newValue)
        
        # Setting multiple properties at once using updateProperties()
        targetPropertyA = indexes.USE_SSL
        changeValueA = True
        targetPropertyB = indexes.SERVER_PORT
        changeValueB = 636
        
        oldValueA = self.auth.getProperty(targetPropertyA)
        oldValueB = self.auth.getProperty(targetPropertyB)
        
        newValues = {
            targetPropertyA:changeValueA,
            targetPropertyB:changeValueB
        }
        
        self.auth.updateProperties(newValues)
        
        newValueA = self.auth.getProperty(targetPropertyA)
        newValueB = self.auth.getProperty(targetPropertyB)
        
        self.assertNotEquals(oldValueA,newValueA)
        self.assertNotEquals(oldValueB,newValueB)
        
if __name__ == '__main__':
    unittest.main()
