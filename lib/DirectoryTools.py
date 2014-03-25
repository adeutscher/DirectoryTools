
__version__ = 0.1

import ldap,re,sys,traceback

import DirectoryToolsIndexes as index
import DirectoryToolsSchemas as schema

DEBUG_LEVEL_NONE = 0
DEBUG_LEVEL_MINOR = 1
DEBUG_LEVEL_MAJOR = 2
DEBUG_LEVEL_EXTREME = 3

class DirectoryTools:

    properties = {
        index.DEBUG_LEVEL:0,
        index.SERVER_ADDRESS:'',
        index.SERVER_PORT:389,
        index.USE_SSL:False,
        index.USE_TLS:False,
        index.MAX_DEPTH:5,
        index.PROXY_USER:'',
        index.PROXY_PASSWORD:'',
        index.BASE_DN:'',
        index.USER_RDN:'',
        index.GROUP_RDN:'',
    }
    
    DEBUG_LEVEL_NONE = 0
    DEBUG_LEVEL_MINOR = 1
    DEBUG_LEVEL_MAJOR = 2
    DEBUG_LEVEL_EXTREME = 3
    
    proxyHandle = False
    
    searchedGroups = []

    def __init__(self,properties=False,template='openldap'):
        
        self.flushCaches()
        
        if template:
            try: 
                self.properties.update(schema.getTemplate(template))
            except:
                print "Schema template '%s' not found. Exiting..." % template
                exit(1)        
        if properties:    
            try:        
                self.properties.update(properties)
            except:
                print "Error initializing DirectoryTools object, properties argument is expected to be a dictionary. Exiting..."
                exit(1)
    '''
    Attempts to do a simple bind to see if the user entered their password correctly.
    
    @return True/False    
    '''
    def authenticate(self,userName,password,userNameIsDN=False):
        
        self.printDebug("Attempting to authenticate user '%s'." % userName, DEBUG_LEVEL_MINOR)

        if userNameIsDN:
            # The username has been provided in DN form for some reason.
            # Don't need to bother resolving or confirming.
            # Authentication will throw the same error whether we have a non-existent user or a bad password.
            userDN = userName
        else:
            userDN = self.resolveUserDN(userName)
            
            if not userDN:
                # Don't bother authenticating if the user doesn't exist.
                self.printDebug("User '%s' cannot be found." % userName, DEBUG_LEVEL_MINOR)
                return False
        
        handle = self.getHandle()
        
        try:
            result = handle.simple_bind_s(userDN,password)
            self.printDebug("Successfully authenticated user '%s'." % userName, DEBUG_LEVEL_MINOR)
            return True
        except ldap.LDAPError:
            traceback.print_exc(file=sys.stdout)
            return False
    '''
    Flush all caches.
    
    TODO: Add arguments/logic to allow the user to flush a specific cache.
    '''
    def flushCaches(self):
        # List of user objects that have been resolved.
        self.resolvedUsers = []
        # Dictionary of UIDs indexed by their DN or their UID that stores their other value.
        self.resolvedUserValues = {}
        
        # List of group objects that have been resolved.
        self.resolvedGroups = []
        # Dictionary of UIDs indexed by their DN or their UID that stores their other value.
        self.resolvedGroupValues = {}
        
        self.classCache = {}
        self.notOfClassCache = {}

    '''
    Combine the relative group base DN with the base DN.
    
    @return combination relative group base DN with the base DN.
    '''
    def getGroupBaseDN(self):
        return "%s%s" % tuple([self.getProperty(index.GROUP_RDN),self.getProperty(index.BASE_DN)])
          
    '''
    List all members of a group.
    
    @return a list of all user accounts. Whether they are distinguished names or not depends on format of the LDAP server's group member property.
    '''    
    def getGroupMembers(self,groupName,returnMembersAsDN=False,objectClassFilter=None,uidAttribute='uid',depth=0):

        if groupName not in self.searchedGroups:
                self.searchedGroups.append(groupName)
                self.printDebug("Getting members of group '%s'." % groupName,DEBUG_LEVEL_MAJOR)
        else:
            self.printDebug("Skipping already searched group: %s" % groupName, DEBUG_LEVEL_MAJOR)
            return []
        
        memberList = []
        
        if depth > self.getProperty(index.MAX_DEPTH):
            self.printDebug("Exceeded max depth of %d." % self.getProperty(index.MAX_DEPTH), DEBUG_LEVEL_MINOR)
            return memberList

        # Compile query for finding group.
        #query = '(&(objectClass=%s)(%s=%s))' % tuple([self.getProperty(index.GROUP_CLASS),groupIdentifier,groupName])
        #self.printDebug("Searching for member users in group '%s'. Query: %s: " % tuple([groupName,query]),DEBUG_LEVEL_MAJOR)
        query = '(%s=%s)'
        self.printDebug("Searching for members in group '%s'." % groupName,DEBUG_LEVEL_MAJOR)
        
        # We want to confirm that the group exists and get its Distinguished Name.
        groupDN = self.resolveGroupDN(groupName)
        
        if not groupDN:
            # Could not find group.
            self.printDebug("Could not locate group: %s" % groupName,DEBUG_LEVEL_MAJOR)
            return []

        members = self.getMultiAttribute(groupDN,self.getProperty(index.MEMBER_ATTRIBUTE))
        for member in members:
                
            if self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
                '''
                Distinguished names may be nested groups.
                We need to double check whether or not this DN is indeed a group.
                '''
                
                if not objectClassFilter:
                    self.printDebug("Adding object '%s' to list (No Filter)." % member, DEBUG_LEVEL_MAJOR)
                    memberList.append(member)
                elif objectClassFilter and self.isObjectOfClass(member,objectClassFilter):
                    # Either we are not filtering by group, or the object at this DN is of the class we want to filter by.
                    self.printDebug("Adding object '%s' to list (Passed Filter)." % member, DEBUG_LEVEL_MAJOR)
                    memberList.append(member)
                
                if self.getProperty(index.NESTED_GROUPS) and not (depth >= self.getProperty(index.MAX_DEPTH)) and self.isObjectGroup(member):
                    '''
                    If this log is being executed we have confirmed three things: 
                    * We want to search in nested groups.
                    * We have not yet exceeded the maximum search depth.
                    * The object is actually a group (kind of important!).
                    '''
                    
                    memberUID = self.resolveGroupUID(member)
                    if memberUID:
                        self.printDebug("Searching within nested group '%s'" % member, DEBUG_LEVEL_MAJOR)
                        memberList.extend(
                            self.getGroupMembers(groupName=memberUID,returnMembersAsDN=True,objectClassFilter=objectClassFilter,uidAttribute=uidAttribute,depth=(depth+1))
                        )
                    else:
                        self.printDebug("Could not resolve UID of nested group '%s'." % member, DEBUG_LEVEL_MAJOR)

            else:
                # POSIX-style members can be trusted to be the type they are labeled as.
                # POSIX-style members will not be nested groups.
                memberList.append(member)
        
        if depth > 0:
            # We are not in the first call of the function. Return the list as we have it right now to be processed at the top level.
            return memberList
        else:
            # Done searching through groups and we're about to sort through the top level. Flushing list of recent searches.
            self.searchedGroups = []
            
        self.printDebug("Finished gathering members of group '%s'. Formatting results." % groupName,DEBUG_LEVEL_MAJOR)
        
        # We want to return a deduped listing of members.
        if returnMembersAsDN and not self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
            # The user has requested the return list in DN format, but the list that they have is not in DN format.
            memberDNList = []
            for i in memberList:
                objectDN = self.resolveObjectDN(i,objectClass=objectClassFilter,uidAttribute=uidAttribute)
                if objectDN:
                    memberDNList.append(objectDN)
                
            return list(set(memberDNList))
        elif not returnMembersAsDN and self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
            # The user has requested that the return list not be in DN format, but the list is in DN format.
            # We will need to resolve the user's DN to a login ID.
            memberUIDList = []
            for i in memberList:
                result = self.getSingleAttribute(dn=i,attribute=uidAttribute)
                if result:
                    memberUIDList.append(result)
            print memberUIDList
            return list(set(memberUIDList))
        else:
            # The list we are currently working on is already in the desired format.
            return list(set(memberList))

    '''
    Attempts to establish a basic connection to the LDAP server.
    '''
    def getHandle(self):
        
        protocol = ('ldap','ldaps')[self.getProperty(index.USE_SSL)]
        
        uri = '%s://%s:%s' % tuple([protocol,self.getProperty(index.SERVER_ADDRESS),self.getProperty(index.SERVER_PORT)])
        self.printDebug("Connection URI: %s" % uri,DEBUG_LEVEL_MAJOR)
        
        connection = ldap.initialize(uri)

        return connection

    def getMultiAttribute(self,dn,attribute):
        return self.getObjectAttribute(dn=dn,attribute=attribute)

    '''
    Simple query to get all values of an attribute for a single object.
    
    @param dn the Distinguished Name that we are searching for.
    @param attribute is the attribute we want to fetch.
    @param returnSingle skip ahead and return a single attribute.
    '''
    def getObjectAttribute(self,dn,attribute,returnSingle=False):
        
        results = self.query('objectClass=*',[attribute],dn)

        try:
            dn,attributes = results[0]
            if returnSingle:
                return attributes[attribute][0]
            else:
                return attributes[attribute]
        except:
            # If we're getting an exception, then the index wasn't found.
            if returnSingle:
                return None
            else:
                return []

    ''' 
    Gets a property value.
    
    If a key is not found, then the script will exit with an error.
    
    @return the value of a key out of either the properties or defaults dictionary.
    '''
    def getProperty(self,key):
        try:
                return self.properties[key]
        except KeyError:
            print "Property '%s' not found! Exiting..." % key
            exit(1)
    
    '''
    Get a connection handle for the lookup proxy.
    
    @return an LDAP connection handle that has been bound to by the lookup user.
    '''
    def getProxyHandle(self):
        
        if not self.proxyHandle:
            # Get a handle for our server.
            connection = self.getHandle()
            
            try:
                # Attempt to bind as the proxy user.
                resultCode = connection.simple_bind_s(self.getProperty(index.PROXY_USER),self.getProperty(index.PROXY_PASSWORD))
                self.proxyHandle = connection
            except ldap.LDAPError:
                # This exception is thrown when the call to connection.simple_bind_s fails.
                print "Proxy connection failed."
                traceback.print_exc(file=sys.stdout)
                exit(1)
            self.printDebug("Successfully created proxy handle.",DEBUG_LEVEL_EXTREME)
        else:
            self.printDebug("Returning cached proxy handle.",DEBUG_LEVEL_EXTREME)
        return self.proxyHandle

    def getSingleAttribute(self,dn,attribute):
        return self.getObjectAttribute(dn=dn,attribute=attribute,returnSingle=True)

    '''
    Combine the relative user base DN with the base DN.
    
    @return combination relative user base DN with the base DN.
    '''
    def getUserBaseDN(self):
        return "%s%s" % tuple([self.getProperty(index.USER_RDN),self.getProperty(index.BASE_DN)])

    def getUsersInGroup(self,groupName,returnMembersAsDN=False):
        return self.getGroupMembers(groupName=groupName,returnMembersAsDN=returnMembersAsDN,objectClassFilter=self.getProperty(index.USER_CLASS),uidAttribute=self.getProperty(index.USER_UID_ATTRIBUTE))

    '''
    Confirms that the specified object is a group.
    
    @param groupDN the DN of the object that we are confirming as a group.
    '''
    def isObjectGroup(self,groupDN):
        return self.isObjectOfClass(objectDN=groupDN,objectClass=self.getProperty(index.GROUP_CLASS))

    '''
    Determines whether or not a user is in a group.
    
    The advantage to using this over getGroupUsers is that the method will short circuit as soon as it finds a matching user.
    
    @param objectName a user identifier.
    @param groupName a group identifier.
    @param objectNameIsDN boolean flag. Set to True if the objectName argument is a Distinguished Name, False for a UID.
    @param groupNameIsDN boolean flag. Set to True if the groupName argument is a Distinguished Name, False for a UID.
    @param objectIdentifier name of UID attribute for the object we want to search for.
    @param objectClass the class of the object we're searching for.
    @param objectBase the base DN to search for this object in.
    '''
    def isObjectInGroup(self,objectName,groupName,objectNameIsDN=False,groupNameIsDN=False,objectIdentifier=False,objectClass=False,objectBase=False,depth=0):
        
        self.printDebug("Searching for user '{0}' in group '{1}'".format(objectName,groupName),DEBUG_LEVEL_MAJOR,spaces=depth)
        
        if groupName in self.searchedGroups:
            # We have already searched in this group.
            self.printDebug("Skipping group '{0}'. Already searched.".format(groupName),DEBUG_LEVEL_MAJOR,spaces=depth)
            if depth == 0:
                self.searchedGroups = []
            return False
        self.searchedGroups.append(groupName)
        
        if int(depth) > self.getProperty(index.MAX_DEPTH):
            self.printDebug("Exceeded max depth of %d." % self.getProperty(index.MAX_DEPTH), DEBUG_LEVEL_MINOR,spaces=depth)
            if depth == 0:
                self.searchedGroups = []
            return False
        
        # We need the DN of the group to get its attributes.
        if groupNameIsDN:
            # No need to resolve, groupName provided as DN.
            groupDN = groupName
        else:
            groupDN = self.resolveGroupDN(groupName)
            if not groupDN:
                # Can't find group, no point in continuing.
                self.printDebug("Cannot locate group '{0}' in order to search for member '{1}' within it. Returning False.".format(groupName,objectName),index.DEBUG_LEVEL_MAJOR,spaces=depth)
                if depth == 0:
                    self.searchedGroups = []
                return False
        
        if not objectNameIsDN and self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
            # If we are using a system which indexes its group members as distinguished names, we must resolve our given UID to a DN for matching.
            searchName = self.resolveObjectDN(objectClass,objectIdentifier,objectName,objectBase)
            if not searchName:    
                # If this DN search does not yield any object, there's no point in continuing with our search.
                if depth == 0:
                    self.searchedGroups = []
                return False
        elif objectNameIsDN and not self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
            # If we are using a system which indexes its group members as UIDs, we must resolve our given DN to a UID.
            objectName  = self.resolveObjectUID(objectName,objectIdentifier)
            if not searchName:
                # Cannot find a UID. No point in continuing.
                if depth == 0:
                    self.searchedGroups = []
                return False
        else:
            # Not a DN, so no need to resolve.
            searchName = objectName
        
        members = self.getMultiAttribute(groupDN,self.getProperty(index.MEMBER_ATTRIBUTE))

        nestedGroupList = []
        
        for member in members:
            # Cycle through group results.
            
            if member == searchName:
                # If we are using a POSIX group, we can trust that the item is of the class we want.
                # If members are DNs, then we have resolved the UID to an existing object.
                if depth == 0:
                    self.searchedGroups = []
                self.printDebug("Verified object '{0}' as a member of group '{1}'".format(objectName,groupName),DEBUG_LEVEL_MAJOR,spaces=depth)
                return True
            elif self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
                
                if member == searchName:
                    self.printDebug("Verified object '{0}' as a member of group '{1}'".format(objectName,groupName),DEBUG_LEVEL_MAJOR,spaces=depth)
                    if depth == 0:
                        self.searchedGroups = []
                    return True
                elif self.getProperty(index.NESTED_GROUPS) and self.isObjectGroup(member):
                    # We have stated that we want to search through nested groups.
                    # The item is a group, and the object is a member of it.
                    
                    # But first, we want to search through other direct memberships
                    # to make sure that the desired property is not here.
                    self.printDebug("Observed group '{0}'. Will search through it if no direct matches are found in this group.".format(member),DEBUG_LEVEL_MAJOR,spaces=depth)
                    nestedGroupList.append(member)
                else:
                    # If the if statement is not triggered, then the object is a object.
                    # Any object type other than the group is irrelevant, placing the else statement for the sake of verbosity.
                    self.printDebug("Observed non-matching object '%s'" % member,DEBUG_LEVEL_MAJOR,spaces=depth)
        
        for nestedGroup in nestedGroupList:
            if self.isObjectInGroup(objectName,self.resolveGroupUID(nestedGroup),objectNameIsDN=objectNameIsDN,groupNameIsDN=groupNameIsDN,objectIdentifier=objectIdentifier,objectClass=objectClass,objectBase=objectBase,depth=(depth+1)):
                if depth == 0:
                    self.searchedGroups = []
                return True
        if depth == 0:
            self.searchedGroups = []
        # Fall back to false.
        return False

    def isObjectOfClass(self,objectDN,objectClass):
        self.printDebug("Checking whether the object at '%s' is of class '%s'" % tuple([objectDN,objectClass]),DEBUG_LEVEL_MAJOR)
        try:
            # Attempt to find the object in the cache.
            if objectDN in self.classCache[objectClass]:
                self.printDebug("Verified object using cache.",DEBUG_LEVEL_MAJOR)
                return True
            elif objectDN in self.notOfClassCache[objectClass]:
                self.printDebug("Cache reports that we could not verify object.",DEBUG_LEVEL_MAJOR)
                return False
        except:
            pass
        classes = self.getMultiAttribute(objectDN,'objectClass')
        if objectClass in classes:
            try:
                self.classCache[objectClass]
            except:
                self.classCache[objectClass] = []
            self.classCache[objectClass].append(objectDN)
            self.printDebug("Verified object.",DEBUG_LEVEL_MAJOR)
            return True
        self.printDebug("Could not verify object.",DEBUG_LEVEL_MAJOR)
        return False

    '''
    Confirms that the specified object is a user. Alias of isObjectOfClass()
    
    @param userDN the DN of the object that we are confirming as a user.
    '''      
    def isObjectUser(self,userDN):
        return self.isObjectOfClass(objectDN=userDN,objectClass=self.getProperty(index.USER_CLASS))

    def isUserInGroup(self,userName,groupName,userNameIsDN=False,groupNameIsDN=False):
        return self.isObjectInGroup(objectName=userName,groupName=groupName,objectNameIsDN=userNameIsDN,groupNameIsDN=groupNameIsDN,objectIdentifier=self.getProperty(index.USER_UID_ATTRIBUTE),objectClass=self.getProperty(index.USER_CLASS),objectBase=self.getUserBaseDN())
    
    def makeSpaces(self,spaceCount=0):
        returnValue = ''
        i = 0
        while i < spaceCount:
            returnValue = "{0}{1}".format(returnValue,' ')
            i = i + 1 
        return returnValue
    
    '''
    Prints a debug message.
    Message will only be printed if the debug level is equal to or greater than the clearance level.
    
    @param message message to print.
    @param secrecyLevel authorization required to print.
    
    @return True if the message was transmitted. False otherwise.
    '''
    def printDebug(self,message,secrecyLevel=100,spaces=0):
        if self.getProperty(index.DEBUG_LEVEL) >= int(secrecyLevel):
            print "{0}DEBUG({1}): {2}".format(self.makeSpaces(spaces),secrecyLevel,message)
            return True
        return False
    
    '''
    Executes an LDAP query.
    
    @param self parent object.
    @param query the query string.
    @param attributes a list of attributes that we wish to fetch.
    @param base the search base.
    
    @return the list of results. References are omitted.
    '''
    def query(self,query='',attributes=None,base=None):
        handle = self.getProxyHandle()
        
        if not base:
            base = self.getProperty(index.BASE_DN)

        returnList = []

        self.printDebug("Executing LDAP search.",DEBUG_LEVEL_EXTREME)
        self.printDebug("    Filter: %s" % str(query),DEBUG_LEVEL_EXTREME)
        self.printDebug("    Base: %s" % str(base),DEBUG_LEVEL_EXTREME)
        
        try:        
            results = handle.search_s(base,ldap.SCOPE_SUBTREE,query,attributes)
        except:
            self.printDebug("BAD QUERY",DEBUG_LEVEL_EXTREME)
            traceback.print_exc(file=sys.stdout)
            return returnList
        for result in results:
            dn,attrs = result
            if dn:
                returnList.append(result)
        return returnList
    
    '''
    Resolve a group DN based on the given index.
    
    @param self the parent object.
    @param groupName the group name we are trying to resolve.
    @param uidAttribute the attribute that groupName can be found in.
    
    @return a tuple. First value is a boolean indicator of success/failure. If the first value is true, then the second value will be the group's distinguished name.
    '''    
    def resolveGroupDN(self,groupName,uidAttribute=False):
        if not uidAttribute:
            uidAttribute = self.getProperty(index.GROUP_UID_ATTRIBUTE)
        if groupName in self.resolvedGroups:
            self.printDebug("Using cached DN for '%s'. Value: %s" % tuple([groupName,self.resolvedGroupValues[groupName]]),DEBUG_LEVEL_MAJOR)
            return self.resolvedGroupValues[groupName]
        returnValue = self.resolveObjectDN(self.getProperty(index.GROUP_CLASS),uidAttribute,groupName,self.getGroupBaseDN())
    
        self.resolvedGroups.append(groupName)
        self.resolvedGroupValues[groupName] = returnValue
        
        if returnValue not in self.resolvedGroups:
            # May as well cache the reverse of this lookup as well.
            self.resolvedGroups.append(returnValue)
            self.resolvedGroupValues[returnValue] = groupName
        return returnValue
        
    ''' 
    Resolve a group's name from a given DN.
    '''
    def resolveGroupUID(self,groupDN,uidAttribute=False):
        if not uidAttribute:
            # No override provided.
            uidAttribute = self.getProperty(index.GROUP_UID_ATTRIBUTE)
        
        query = "(&(objectClass=%s)(%s=*))" % tuple([self.getProperty(index.GROUP_CLASS),self.getProperty(index.GROUP_UID_ATTRIBUTE)])
        self.printDebug("Query for value of '%s' for DN of '%s': %s" % tuple([uidAttribute,groupDN,query]), DEBUG_LEVEL_MAJOR)

        # Checking cached values.
        if groupDN in self.resolvedGroupValues:
            self.printDebug("Using cached UID for '%s'. Value: %s" % tuple([groupDN,self.resolvedGroupValues[groupDN]]),DEBUG_LEVEL_MAJOR)
            return self.resolvedGroupValues[groupDN]
        
        result = self.query(query,[uidAttribute],groupDN)
        
        try:
            for i in result:
                # We only care about the first result. There should only be one, to boot.
                dn, attributes = i
                
                # Grabbing the UID attribute.
                # If the UID value is incorrect, the exception will happen here.
                returnValue = attributes[uidAttribute][0]
                
                self.resolvedUsers.append(groupDN)
                self.resolvedUserValues[groupDN] = returnValue
                if returnValue not in self.resolvedUsers:
                    # May as well cache the reverse of this lookup as well.
                    self.resolvedUsers.append(returnValue)
                    self.resolvedUserValues[returnValue] = groupDN
                return returnValue
        except:
            # Unable to find the group ID.
            
            self.resolvedGroups.append(groupDN)
            self.resolvedGroupValues[groupDN] = None
            return False
        
    '''
    Method to resolve an instance of a class.
    
    @param self the parent object.
    @param class the objectClass that we want to resolve for.
    @param objectAttribute the attribute that objectName can be found in.
    @param objectName the group name we are trying to resolve.
    @param base the search base.
    
    @return a tuple drawn from resolveObjectDN. First value is a boolean indicator of success/failure. If the first value is true, then the second value will be the object's distinguished name.
    '''
    def resolveObjectDN(self,objectClass,indexAttribute,objectName,base):
        query = '(&(objectClass=%s)(%s=%s))' % tuple([objectClass,indexAttribute,objectName])
        self.printDebug("Resolving the DN of an item with the objectClass '%s': %s" % tuple([objectClass,query]),DEBUG_LEVEL_MAJOR)
        
        result = self.query(query,['distinguishedName'],base=base)
        if len(result) > 0:
            dn,attributes = result[0]
            if dn:
                return dn
            return False
        
    '''
    Get the UID of an object. Alias for getSingleAttribute()
    
    @param objectDN Distinguished Name to search in.
    @param objectIdentifier the single-valued attribute representing an object's unique identifier.
    '''
    def resolveObjectUID(self,objectDN,objectIdentifier):
        return self.getSingleAttribute(dn=objectDN,attribute=objectIdentifier)

    '''
    Resolve a user DN based on the given index.
    
    @param self the parent object.
    @param userName the username we are trying to resolve.
    @param uidAttribute the attribute that the userName can be found in.
    
    @return a tuple drawn from resolveObjectDN. First value is a boolean indicator of success/failure. If the first value is true, then the second value will be the user's distinguished name.
    '''
    def resolveUserDN(self,userName,uidAttribute=False):
        if not uidAttribute:
            uidAttribute = self.getProperty(index.USER_UID_ATTRIBUTE)
        if userName in self.resolvedUsers:
            self.printDebug("Using cached DN for '%s'. Value: %s" % tuple([userName,self.resolvedUserValues[userName]]),DEBUG_LEVEL_MAJOR)
            return self.resolvedUserValues[userName]
        returnValue = self.resolveObjectDN(self.getProperty(index.USER_CLASS),uidAttribute,userName,self.getUserBaseDN())
        
        self.resolvedUsers.append(userName)
        self.resolvedUserValues[userName] = returnValue
        
        if returnValue not in self.resolvedUsers:
            # May as well cache the reverse of this lookup as well.
            self.resolvedUsers.append(returnValue)
            self.resolvedUserValues[returnValue] = userName
        return returnValue

    ''' 
    Resolve a user's login name from a given DN.
    '''
    def resolveUserUID(self,userDN,uidAttribute=False):
        if not uidAttribute:
            # No override provided.
            uidAttribute = self.getProperty(index.USER_UID_ATTRIBUTE)
        
        query = "(&(objectClass=%s)(%s=*))" % tuple([self.getProperty(index.USER_CLASS),self.getProperty(index.USER_UID_ATTRIBUTE)])
        self.printDebug("Query for value of '%s' for DN of '%s': %s" % tuple([uidAttribute,userDN,query]), DEBUG_LEVEL_MAJOR)

        # Checking cached values.
        if userDN in self.resolvedUsers:
            self.printDebug("Using cached UID for '%s'. Value: %s" % tuple([userDN,self.resolvedUserValues[userDN]]),DEBUG_LEVEL_MAJOR)
            return self.resolvedUserValues[userDN]
        
        result = self.query(query,[uidAttribute],userDN)
        
        try:
            for i in result:
                # We only care about the first result. There should only be one, to boot.
                dn, attributes = i
                
                # Grabbing the UID attribute.
                # If the UID value is incorrect, the exception will happen here.
                returnValue = attributes[uidAttribute][0]
                
                self.resolvedUsers.append(userDN)
                self.resolvedUserValues[userDN] = returnValue
                # May as well cache the reverse of this lookup as well.
                if returnValue not in self.resolvedUsers:
                    self.resolvedUsers.append(returnValue)
                    self.resolvedUserValues[returnValue] = userDN
                return returnValue
        except:
            # Unable to find the user ID.
            self.resolvedUsers.append(userDN)
            self.resolvedUserValues[userDN] = None
            traceback.print_exc(file=sys.stdout)
            return None
    '''
    Set a single property.
    '''
    def setProperty(self,key,value):
        properties[key] = value
