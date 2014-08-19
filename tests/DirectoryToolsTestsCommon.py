#!/usr/bin/python

import DirectoryTools
import DirectoryToolsIndexes as indexes
import unittest

class DirectoryToolsTestsCommon(object):
    '''
    Common tests that address multiple LDAP implementations. Child classes multiple inheritance to import these tests without running the test suite without a headless set of tests with no setUp method.
    
    Exceptions that are not valid for a specific LDAP server will be skipped in the overriding methods.
    
    '''
    
    def test_authenticate(self):
        '''
        Attempt to authenticate a user. Demonstrates a successful password and then modifies the password to create a failure.
        '''
        successfulAuth = self.auth.authenticate(self.userA,self.userPassword)
        self.assertTrue(successfulAuth)
        
        failedAuth = self.auth.authenticate(self.userA,self.userPassword + 'nope')
        self.assertFalse(failedAuth)
    
    def test_getNestedGroupMembers(self):
        '''
        Tests rerieving information on which users belong to a group. Uses nesting to also collect all indirect members.
        '''        
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

    def test_getGroupMembers(self):
        '''
        Tests retrieving information in which users belong to a group. Does not search in nested groups, and returns only direct memberships.
        '''
        # Test getting group members without nesting. Direct user memberships only.
        self.auth.setProperty(indexes.NESTED_GROUPS,False)
        
        searchedGroup = self.serviceGroup
        directMemberList = self.auth.getUsersInGroup(searchedGroup)
        print 'Displaying members of {0} group: {1}'.format(searchedGroup,directMemberList)
        self.assertEquals(len(directMemberList),self.serviceGroupDirectUserMemberCount)
        
        # Search and retrieved distinguished names. A DN shall be considered valid if it is longer than the login name.
        directMemberDNList = self.auth.getUsersInGroup(searchedGroup,returnMembersAsDN=True)
        print 'Displaying members of {0} group: {1}'.format(searchedGroup,directMemberDNList)
        
        # Make sure we have the same number of results as before.
        self.assertEquals(len(directMemberDNList),len(directMemberList))
        
        for i in range(len(directMemberDNList)):
            self.assertTrue(len(directMemberDNList[i]) > len(directMemberList[i]))

    def test_getMultiAttribute(self):
        '''
        Tests the retrieval of a multi-valued attribute from an object. DirectoryTools returns multi-valued objects as lists.
        '''
        
        targetAttribute = 'memberOf'
        targetDN = self.auth.resolveGroupDN(self.employeeGroup)
        
        attributeList = self.auth.getMultiAttribute(targetDN,self.targetAttribute)
        
        print 'Displaying values of the attribute "{0}" for the object "{1}": {2}'.format(targetAttribute,targetDN,attributeList)
        
    def test_getObjectAttributes(self):
        '''
        Need to get multiple types of attributes at the same time.
        '''         
        targetDN = self.auth.resolveGroupDN(self.employeeGroup)
        
        results = self.auth.getObjectAttributes(targetDN,self.targetAttributes)
        
        print "Results: {0}".format(results)
        
        for i in results:
                self.assertTrue(len(results[i]) > 0)
        
    def test_isUserInGroup(self):
        '''
        Test that we can detect whether or not a user is in the specified group.
        '''
    
        targetGroup = self.serviceGroup
        
        targetMemberUID = self.userC
        targetNonMemberUID = self.userD
        
        # Testing with UID names, not distinguished names.
        
        isMember = self.auth.isUserInGroup(targetMemberUID,targetGroup)
        self.assertTrue(isMember)
        isNotMember = self.auth.isUserInGroup(targetNonMemberUID,targetGroup)
        self.assertFalse(isNotMember)
        
    
    def test_properties(self):
        '''
        Test the retrieval and manipulation of properties.
        '''    
        # Setting this boolean property to the inverse of its previous value.
        targetProperty = indexes.NESTED_GROUPS
        oldValue = self.auth.getProperty(targetProperty)
        self.auth.setProperty(targetProperty,not bool(oldValue))
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
    print "Run these tests through an inheriting class that creates a connection to an LDAP server through DirectoryTools. Aborting..."
    exit(1)
