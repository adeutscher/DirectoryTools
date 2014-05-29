
__version__ = 0.1

import ldap,re,sys,traceback
from time import time
from datetime import datetime

import DirectoryToolsIndexes as index
import DirectoryToolsSchemas as schema

DEBUG_LEVEL_NONE = 0
DEBUG_LEVEL_MINOR = 1
DEBUG_LEVEL_MAJOR = 2
DEBUG_LEVEL_EXTREME = 3

class DirectoryTools:
    """
    Class containing methods for queryin an LDAP server.
    """
    
    ## Default properties.
    properties = {
        index.DEBUG_LEVEL:0,
        index.SERVER_ADDRESS:'',
        index.SERVER_PORT:389,
        index.USE_SSL:False,
        index.USE_TLS:False,
        index.LDAP_PROPERTIES:{},
        index.MAX_DEPTH:5,
        index.NESTED_GROUPS:False,
        index.PROXY_USER:'',
        index.PROXY_PASSWORD:'',
        index.BASE_DN:'',
        index.USER_RDN:'',
        index.GROUP_RDN:'',
        index.PROXY_IS_ANONYMOUS:False,
    }
    
    ## No debugging.
    DEBUG_LEVEL_NONE = 0
    ## Debug level 1
    DEBUG_LEVEL_MINOR = 1
    ## Debug level 2
    DEBUG_LEVEL_MAJOR = 2
    ## Debug level 3
    DEBUG_LEVEL_EXTREME = 3
    
    ## Handle used to search the directory server.
    proxyHandle = False
    
    ## Cache for reducing the number of queries that need to be run, especially common ones like resolving a DN.
    cache = {}
    

    def __init__(self,properties=False,template='openldap'):
        '''
        Initializes the DirectoryTools object.
        
        Args:
            properties: Dictionary of properties. Can be updated through setProperties or updateProperties.
            template: String describing a template schema that defines common properties given LDAP server implementation. If the schema is not found, then the program will exit.
        '''
        
        if template:
            try: 
                self.properties.update(schema.getTemplate(template))
            except:
                print "Schema template '{0}' not found. Exiting...".format(template)
                exit(1)        
        if properties:    
            try:        
                self.properties.update(properties)
            except:
                print "Error initializing DirectoryTools object, properties argument is expected to be a dictionary. Exiting..."
                exit(1)
    
    def authenticate(self,userName,password,userNameIsDN=False):
        '''
        Attempts to do a simple bind to see if the user entered their password correctly.
        
        Args:
            userName: User's login string. Can be either a login name or a distinguished name.
            password: User's password.
            userNameIsDN: True if the provided username is already a DN. If set to False, the method will attempt to resolve the DN first.
            
        Returns:
            True if the user successfully authenticates, false if there is an error.
        '''
        
        self.printDebug("Attempting to authenticate user '{0}'.".format(userName), DEBUG_LEVEL_MINOR)

        if userNameIsDN:
            # The username has been provided in DN form.
            # Don't need to bother resolving or confirming.
            # Authentication will throw the same error whether we have a non-existent user or a bad password.
            userDN = userName
        else:
            userDN = self.resolveUserDN(userName)
            
            if not userDN:
                # Don't bother authenticating if the user doesn't exist.
                self.printDebug("User '{0}' cannot be found.".format(userName), DEBUG_LEVEL_MINOR)
                return False
        
        handle = self.getHandle()
        
        try:
            # Attempt to do a simple bind. If anything goes wrong, we'll be thrown to our 'except'.
            result = handle.simple_bind_s(userDN,password)
            self.printDebug("Successfully authenticated user '{0}'.".format(userName), DEBUG_LEVEL_MINOR)
            return True
        except ldap.LDAPError:
            if(self.getProperty(index.DEBUG_LEVEL) >= DEBUG_LEVEL_EXTREME):
                traceback.print_exc(file=sys.stdout)
            return False
            
    def flushCaches(self,category=False,cacheId=False):
        '''
        Clears out caches.
        
        Args:
            category: The category of cache to clear.
            cacheId: Instance within cache to clear.
            
        Returns:
            None
        '''
        try:
            if type(category) is str and type(cacheId) is str:
                # A specific cache ID was requested in a category.
                del self.cache[category][cacheId]
            elif type(category) is str:
                # A category was specified, but not a cache Id.
                # Flush all items in this category.
                if category in self.cache:
                    del self.cache[category]
            else:
                # No category was specified, flushing all caches by re-declaring the cache.
                
                ## Cache for reducing the number of queries that need to be run, especially common ones like resolving a DN.
                self.cache = {}
        except:
            pass
    
    def getGroupBaseDN(self):
        '''
        Combine the relative group base DN with the base DN.
        
        Returns:
            A string composed of a combination of the relative group base DN provided by the GROUP_RDN property and the base DN provided by the BASE_DN property.
        '''
        return "{0}{1}".format(self.getProperty(index.GROUP_RDN),self.getProperty(index.BASE_DN))
          

    def getGroupMembers(self,groupName,groupNameIsDN=False,returnMembersAsDN=False,objectClassFilter=None,uidAttribute='uid',depth=0,cacheId=True):
        '''
        List all members of a group.
        
        Args:
            groupName: A string specifying the name of the group.
            groupNameIsDN: True if the provided group name is already a DN.
            returnMembersAsDN: If set to True, specifies that we want our results to be formatted as a list of distinguished names. If set to False, specifies that we want our results to be formatted as a list of login names.
            objectClassFilter: String specifing the class to filter by. If the LDAP server stores group members as distinguished names, only those who are of the specified class will be shown. If set to None (default), group members will not be trusted to be of the intended class. LDAP servers that do not store members as distinguished names are trusted to be of the intended type.
            uidAttribute: Attribute containing the user's user login Id. To be used if the user wants their return list to be distinguished names when the server indexes group members by UID.
            depth: A count of how many times the function has been called. To be used in recursive calls.
            cacheId: ID of the cache that stores a list of searched groups.
        
        Returns:
            A list of all user accounts. Whether they are distinguished names or not depends on format of the LDAP server's group member property.
        '''
        
        cacheCategory = 'searchedGroups'
        cacheId = self.initCache(cacheCategory,cacheId)
        
        if not groupNameIsDN:
            # We want to confirm that the group exists and get its Distinguished Name.
            groupDN = self.resolveGroupDN(groupName,self.getProperty(index.GROUP_UID_ATTRIBUTE))
            if not groupDN:
                self.printDebug("Could not locate group: {0}".format(groupName),DEBUG_LEVEL_MAJOR)
                return []
        else:
            # Group name is already a DN.
            groupDN = groupName

        # Making sure that we have not already searched this group.
        if groupName not in self.cache[cacheCategory][cacheId]:
                self.cache[cacheCategory][cacheId][groupName] = 1
                self.printDebug("Getting members of group '{0}'.".format(groupName),DEBUG_LEVEL_MAJOR)
        else:
            self.printDebug("Skipping already searched group: {0}".format(groupName), DEBUG_LEVEL_MAJOR)
            return []
        
        memberList = []
        
        if depth > self.getProperty(index.MAX_DEPTH):
            self.printDebug("Exceeded max depth of {1}.".format(self.getProperty(index.MAX_DEPTH)), DEBUG_LEVEL_MINOR)
            return memberList

        # Compile query for finding group.
        #query = '(&(objectClass=%s)(%s=%s))' % tuple([self.getProperty(index.GROUP_CLASS),groupIdentifier,groupName])
        #self.printDebug("Searching for member users in group '%s'. Query: %s: " % tuple([groupName,query]),DEBUG_LEVEL_MAJOR)
        query = '(%s=%s)'
        self.printDebug("Searching for members in group '{0}'.".format(groupName),DEBUG_LEVEL_MAJOR)

        members = self.getMultiAttribute(groupDN,self.getProperty(index.MEMBER_ATTRIBUTE))
        for member in members:
                
            if self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
                # Distinguished names may be nested groups.
                # We need to double check whether or not this DN is indeed a group.
                
                
                if not objectClassFilter:
                    self.printDebug("Adding object '{0}' to list (No Filter).".format(member), DEBUG_LEVEL_MAJOR)
                    memberList.append(member)
                elif objectClassFilter and self.isObjectOfClass(member,objectClassFilter):
                    # Either we are not filtering by group, or the object at this DN is of the class we want to filter by.
                    self.printDebug("Adding object '{0}' to list (Passed Filter).".format(member), DEBUG_LEVEL_MAJOR)
                    memberList.append(member)
                
                if self.getProperty(index.NESTED_GROUPS) and not (depth >= self.getProperty(index.MAX_DEPTH)) and self.isObjectGroup(member):
                    # If this section is being executed we have confirmed three things: 
                    # * We want to search in nested groups.
                    # * We have not yet exceeded the maximum search depth.
                    # * The object is actually a group (kind of important!).
                    
                    self.printDebug("Searching within nested group '{0}'".format(member), DEBUG_LEVEL_MAJOR)
                    memberList.extend(
                        self.getGroupMembers(groupName=member,groupNameIsDN=True,returnMembersAsDN=True,objectClassFilter=objectClassFilter,uidAttribute=uidAttribute,depth=(depth+1))
                    )

            else:
                # POSIX-style members can be trusted to be the type they are labeled as.
                # POSIX-style members will not be nested groups.
                memberList.append(member)
        
        if depth > 0:
            # We are not in the first call of the function. Return the list as we have it right now to be processed at the top level.
            return memberList
        
        # Begin top-level processing. The following code should only be processed if we're in the top call of this method.
            
        self.printDebug("Finished gathering members of group '{0}'. Formatting results.".format(groupName),DEBUG_LEVEL_MAJOR)
        
        # We want to return a deduped listing of members.
        if returnMembersAsDN and not self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
            # The user has requested the return list in DN format, but the list that they have is not in DN format.
            memberDNList = []
            for i in memberList:
                objectDN = self.resolveObjectDN(objectName=i,objectClass=objectClassFilter,indexAttribute=uidAttribute)
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
            return list(set(memberUIDList))
        else:
            # The list we are currently working on is already in the desired format.
            return list(set(memberList))

    
    def getHandle(self):
        '''
        Attempts to establish a basic connection to the LDAP server.
        
        Returns:
            An initialized LDAP connection. Binding to the server is done in separate methods.
        '''
        
        protocol = ('ldap','ldaps')[self.getProperty(index.USE_SSL)]
        
        uri = '{0}://{1}:{2}'.format(protocol,self.getProperty(index.SERVER_ADDRESS),self.getProperty(index.SERVER_PORT))
        self.printDebug("Connection URI: {0}".format(uri),DEBUG_LEVEL_MAJOR)
        
        connectionProperties = self.getProperty(index.LDAP_PROPERTIES)
        
        connection = ldap.initialize(uri)
        
        for i in connectionProperties:
            self.printDebug('Applying connection property \'{0}\' to connection. Value: \'{1}\''.format(i,connectionProperties[i]),self.DEBUG_LEVEL_MAJOR)
            connection.set_option(i,connectionProperties[i])
        
        return connection

    def getMultiAttribute(self,dn,attribute):
        '''
        Get a single multi-valued attribute from the server. Alias for getObjectAttribute.
        
        Args:
            dn: Distinguished name to get the attribute from.
            attribute: Attribute to search for.
        '''
        return self.getObjectAttribute(dn=dn,attribute=attribute)

    def getMultiAttributes(self,dn,attributes):
        '''
        Get multiple attributes from the server for the specified object.
        
        Args:
            dn: Distinguished name to get attributes from.
            attributes: List of attributes to search for.
        '''
        results = self.query('objectClass=*',attributes,dn)
        try:
            dn,attributes = results[0]
            return attributes
        except:
            # Assuming the index wasn't found.
            # Return an empty dictionary.
            return {}

    def getObjectAttribute(self,dn,attribute,returnSingle=False):
        '''
        Simple query to get all values of an attribute for a single object.
        
        Args:
            dn: The distinguished name of the object that we are getting attributes from.
            attribute: the attribute we want to fetch.
            returnSingle: If True, the method will only return one value of the property as a string. If the attribute can be a multi-valued attribute, only the first result for that attribute will be shown.
        '''
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

    def getProperty(self,key,exitOnFail=True,printDebugMessage=True):
        ''' 
        Gets a property value.
        
        Args:
            key: Name of the property to retrieve. Recommended to go through the values in DirectoryToolsIndexes.
            exitOnFail: If set to True, the script will exit with an error code if the key is not found in our properties.
            printDebugMessage: Since printDebug relies on this method, this is our current solution for avoiding an endless loop. Needs improvement.
            
        Returns:
            The value of a key out of either the properties or defaults dictionary.
        '''
        
        try:
            if printDebugMessage:
                self.printDebug("Fetching property '{0}'".format(key),self.DEBUG_LEVEL_MINOR)
            return self.properties[key]
        except KeyError:
            if exitOnFail:
                print "Property '{0}' not found. Exiting...".format(key)
                exit(1)
            elif printDebugMessage:
                self.printDebug("Property '{0}' not found.".format(key),self.DEBUG_LEVEL_MINOR)
                
            return None

    def getProxyHandle(self):
        '''
        Get a connection handle for the lookup proxy.
        
        If the PROXY_IS_ANONYMOUS property is set to False, the method will attempt to bind to the server using the values of the PROXY_USER and PROXY_PASSWORD properties.
        
        If the PROXY_IS_ANONYMOUS property is set to True, then the method will skip attempting to bind.
                
        Returns:
            An LDAP connection handle to be used by the object to retrieve information from the LDAP server.
        '''
        
        if not self.proxyHandle:
            # Get a handle for our server, if one is not already present.
            connection = self.getHandle()
            
            try:
                if not self.getProperty(index.PROXY_IS_ANONYMOUS):
                    # Attempt to bind as the proxy user if we aren't searching anonymously.
                    resultCode = connection.simple_bind_s(self.getProperty(index.PROXY_USER),self.getProperty(index.PROXY_PASSWORD))
                self.proxyHandle = connection
            except ldap.LDAPError as e:
                # This exception is thrown when the call to connection.simple_bind_s fails.
                print "Proxy connection failed."
                print e
                if e.args[0]['desc'] == 'Invalid credentials':
                    # The error happened because the proxy connection was given the wrong credentials.
                    print "Invalid proxy credentials."
                    exit(2)
                    
                
                traceback.print_exc(file=sys.stdout)
                exit(1)
            self.printDebug("Successfully created proxy handle.",DEBUG_LEVEL_EXTREME)
        else:
            self.printDebug("Returning cached proxy handle.",DEBUG_LEVEL_EXTREME)
        return self.proxyHandle

    def getSingleAttribute(self,dn,attribute):
        '''
        Retrieve a single attribute from a server. Mostly an alias of getObjectAttribute.
        
        Args:
            dn: The distinguished name to retreive the attribute from.
            attribute: The attribute to search for.
            
        Returns:
            String value of an attribute.
        '''
        return self.getObjectAttribute(dn=dn,attribute=attribute,returnSingle=True)

    def getUserBaseDN(self):
        '''
        Combine the relative group base DN with the base DN.
        
        Returns:
            A string composed of a combination of the relative user base DN (indexes.USER_RDN) and the base DN (indexes.BASE_DN)
        '''
        return "{0}{1}".format(self.getProperty(index.USER_RDN),self.getProperty(index.BASE_DN))

    def getUsersInGroup(self,groupName,returnMembersAsDN=False):
        '''
        Alias of getGroupMembers(), pre-configured for retrieving user objects.
        
        Args:
            groupName: Name of the group to search in.
            returnMembersAsDN: If True, the list that is returned will be a list of distinguished names. If False, the list that is returned will be a list of user UIDs.
            
        Returns:
            A list of users, formatted as either UIDs or distinguished names.
        '''
        return self.getGroupMembers(groupName=groupName,returnMembersAsDN=returnMembersAsDN,objectClassFilter=self.getProperty(index.USER_CLASS),uidAttribute=self.getProperty(index.USER_UID_ATTRIBUTE))


    def initCache(self,category='general',cacheId=True):
        '''
        Ensures that a cache is initialized. A specific cache will be a dictionary indexed by cacheId, which is nested in a cache for categories.
        
        Args:
            category: The general category of the cache. For example, 'searchedGroups', 'resolvedDNs'
            cacheId: If set to True, the method will generate a new cache ID using a UNIX timestamp and the current microseconds. If a string is provided, we will ensure use the string as our cacheId value.
            
        Returns:
            A string cacheId being used.
        '''
        defaultCacheId = 'general'
        
        # Make sure that the cache object is initialized.   
        try:
            if type(self.cache) is not dict:
                self.cache = {}
        except NameError:
            self.cache = {}
            
        # Make sure that the category is initialized.
        if category not in self.cache:
            self.cache[category] = {}
        
        # Confirm the cache ID that we'll be working with.
        if cacheId and type(cacheId) is bool:
            # Need to generate a new cache Id.
            
            # Using a UNIX timestamp in milliseconds to get my cache Id.
            timeObj = datetime.now()
            cacheId =  str(time()) + str(timeObj.microsecond)
        elif cacheId:
            # We have been given a cache Id. If it doesn't already exist, we need to make it.
            
            # Make sure that we are working with a string.
            cacheId = str(cacheId)
        else:
            # Not using a specific cache Id. Defaulting to general.
            cacheId = defaultCacheId
            
        # Make sure that the cache ID of the category is initialized.
        # Do not overwrite an existing dictionary, but correct any non-dictionary that has snuck in.
        if cacheId not in self.cache[category] or type(self.cache[category][cacheId]) is not dict:
            self.cache[category][cacheId] = {}
        
        # Return the cache id that we are using. A recursive function must use the same cache Id.
        return cacheId

    
    def isObjectGroup(self,groupDN):
        '''
        Confirms that the specified object is a group by virtue of having an objectClass value of the GROUP_CLASS property. Pre-configured alias of isObjectOfClass().
        
        Args:
            groupDN: The DN of the object that we are confirming as a group.
            
        Returns:
            True if the object is a member of a group, false otherwise.
        '''
        return self.isObjectOfClass(objectDN=groupDN,objectClass=self.getProperty(index.GROUP_CLASS))

    def isObjectInGroup(self,objectName,groupName,objectNameIsDN=False,groupNameIsDN=False,objectIdentifier=False,objectClass=False,objectBase=False,depth=0,cacheId=True):
        '''
        Determines whether or not a user is in a group. This is a will recursively call itself until it exceeds the value of the MAX_DEPTH property.
        
        The advantage to using this over checking against the results of getGroupUsers is that the method will stop and return a result as soon as it finds a matching user.
        
        Args:
            objectName: Name of the object to search for.
            groupName: Name of the group.
            objectNameIsDN: Set to True if the objectName argument is a distinguished name, False for a UID.
            groupNameIsDN: Set to True if the groupName argument is a distinguished name, False for a UID.
            objectIdentifier: The name of UID attribute for the object we want to search for.
            objectClass: The class of the object we're searching for.
            objectBase: The distinguished name of the object that we are searching for.
            depth: Describes which iteration of the method we are currently working in. If the depth exceeds the MAX_DEPTH property, we will automatically return False.
            cacheId: Cache identifier for this chain of calls.
            
        Returns:
            True if the object is a member of a group, False otherwise.
        '''
        
        cacheCategory='searchedGroups'
        cacheId = self.initCache(cacheCategory,cacheId)
        
        self.printDebug("Searching for user '{0}' in group '{1}'".format(objectName,groupName),DEBUG_LEVEL_MAJOR,spaces=depth)
        
        if groupName in self.cache[cacheCategory][cacheId]:
            # We have already searched in this group.
            self.printDebug("Skipping group '{0}'. Already searched.".format(groupName),DEBUG_LEVEL_MAJOR,spaces=depth)
            return False
        self.cache[cacheCategory][cacheId][groupName] = 1
        
        if int(depth) > self.getProperty(index.MAX_DEPTH):
            self.printDebug("Exceeded max depth of {0}.".format(self.getProperty(index.MAX_DEPTH)), DEBUG_LEVEL_MINOR,spaces=depth)
            return False
        
        # We need the DN of the group to get its attributes.
        if groupNameIsDN:
            # No need to resolve, groupName provided as DN.
            groupDN = groupName
        else:
            # Group DN needs to be resolved, UID was provided.
            groupDN = self.resolveGroupDN(groupName)
            if not groupDN:
                # Can't find group, no point in continuing.
                self.printDebug("Cannot locate group '{0}' in order to search for member '{1}' within it. Returning False.".format(groupName,objectName),index.DEBUG_LEVEL_MAJOR,spaces=depth)
                return False
        
        if not objectNameIsDN and self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
            # If we are using a system which indexes its group members as distinguished names, we must resolve our given UID to a DN for matching.
            searchName = self.resolveObjectDN(objectClass,objectIdentifier,objectName,objectBase)
            if not searchName:    
                # If this DN search does not yield any object, there's no point in continuing with our search.
                return False
        elif objectNameIsDN and not self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
            # If we are using a system which indexes its group members as UIDs, we must resolve our given DN to a UID.
            objectName  = self.resolveObjectUID(objectName,objectIdentifier)
            if not searchName:
                # Cannot find a UID. No point in continuing.
                return False
        else:
            # Not a DN, so no need to resolve.
            searchName = objectName
        
        members = self.getMultiAttribute(groupDN,self.getProperty(index.MEMBER_ATTRIBUTE))
        
        # This list will hold group definitions until we are done looking through non-group objects.
        nestedGroupList = []
        
        if not self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
            # Groups in the LDAP server do not store its member properties as distinguished names.
        
            if searchName in members:
                # If we are using a POSIX group, we can trust that the item is of the class we want.
                # If members are DNs, then we have resolved the UID to an existing object.
                self.printDebug("Verified object '{0}' as a member of group '{1}'".format(objectName,groupName),DEBUG_LEVEL_MAJOR,spaces=depth)
                return True
        
        else:
            # Groups in the LDAP server stores its member properties as distinguished names.
            
            # self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN) is true
            # We cannot count on the objects in this group to only be users.
            for member in members:
                # Cycle through group results.
                
                if member == searchName:
                    self.printDebug("Verified object '{0}' as a member of group '{1}'".format(objectName,groupName),DEBUG_LEVEL_MAJOR,spaces=depth)
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
                    self.printDebug("Observed non-matching object '{0}'".format(member),DEBUG_LEVEL_MAJOR,spaces=depth)
        
            # We have completed cycling through the memberList variable for users, and have not found a matching user.
            for nestedGroup in nestedGroupList:
                if self.isObjectInGroup(objectName,self.resolveGroupUID(nestedGroup),objectNameIsDN=objectNameIsDN,groupNameIsDN=groupNameIsDN,objectIdentifier=objectIdentifier,objectClass=objectClass,objectBase=objectBase,depth=(depth+1),cacheId=cacheId):
                    return True
        # Fall back to false if we have not gotten a True response back by this point.
        return False

    def isObjectOfClass(self,objectDN,objectClass):
        '''
        Check to see if an object has a certain objectClass value.
        
        Args:
            objectDN: the distinguished name of the object that we want to verify.
            objectClass: the class value that we want to check for.
            
        Returns:
            True if the object is of the specified class, False if it is not.
        '''
        
        cacheCategory='classCache'
        cacheId=self.initCache(cacheCategory,objectClass)
        
        self.printDebug("Checking whether the object at '{0}' is of class '{1}'".format(objectDN,cacheId),DEBUG_LEVEL_MAJOR)
        
        # Attempt to find the object in the cache.
        if objectDN in self.cache[cacheCategory][cacheId]:
            if self.cache[cacheCategory][cacheId][objectDN]:
                self.printDebug("Verified object as being of class '{0}' using cache.".format(cacheId),DEBUG_LEVEL_MAJOR)
                return True
            else:
                self.printDebug("Cache reports that we could not verify object as being of class '{0}'.".format(cacheId),DEBUG_LEVEL_MAJOR)
                return False
            
        classes = self.getMultiAttribute(objectDN,'objectClass')
        if objectClass in classes:
            self.cache[cacheCategory][cacheId][objectDN] = True
            self.printDebug("Verified object as being of class '{0}' using cache.".format(cacheId),DEBUG_LEVEL_MAJOR)
            return True
        else:
            self.cache[cacheCategory][cacheId][objectDN] = False
            self.printDebug("Cache reports that we could not verify object as being of class '{0}'.".format(cacheId),DEBUG_LEVEL_MAJOR)
            return False

    def isObjectUser(self,userDN):
        '''
        Confirms that the specified object is a group by virtue of having an objectClass value of the USER_CLASS property. Pre-configured alias of isObjectOfClass().
        
        Args:
            userDN: The DN of the object that we are confirming as a user.
            
        Returns:
            True if the object is a member of a user, false otherwise.
        '''
        return self.isObjectOfClass(objectDN=userDN,objectClass=self.getProperty(index.USER_CLASS))

    def isUserInGroup(self,userName,groupName,userNameIsDN=False,groupNameIsDN=False):
        '''
        Checks to see if a user is in the specified group. Pre-configured alias of isObjectInGroup()
        
        Args:
            userName: The name of the user to be checked.
            groupName: The name of the group that we are checking in.
            userNameIsDN: True if the value of userName is a distinguished name. If False, it is a UID.
            groupNameIsDN: True if the value of groupName is a distinguished name. If False, it is a UID.
            
        Returns:
            True if the user is in the group, False if they are not.
            
        '''
        return self.isObjectInGroup(objectName=userName,groupName=groupName,objectNameIsDN=userNameIsDN,groupNameIsDN=groupNameIsDN,objectIdentifier=self.getProperty(index.USER_UID_ATTRIBUTE),objectClass=self.getProperty(index.USER_CLASS),objectBase=self.getUserBaseDN())
    
    def makeSpaces(self,spaceCount=0):
        '''
        Pad out a message with spaces.
        
        Args:
            spaceCount: The number of spaces to pad by.
            
        Returns:
            A string of spaces. Length equals spaceConut.
        '''
    
        returnValue = ''
        i = 0
        while i < spaceCount:
            returnValue = "{0}{1}".format(returnValue,' ')
            i = i + 1 
        return returnValue

    def printDebug(self,message,secrecyLevel=100,spaces=0):
        '''
        Prints a debug message.
        
        The message will only be printed if the debug level is equal to or greater than the clearance level.
        
        Args:
            message: The message to print.
            secrecyLevel: The authorization required to print. The DEBUG_LEVEL property must be equal to or greater than this secrecy level to print the message.
            spaces: The number of spaces to indent the debug string by.
            
        Returns:
            True if the message was sent, False otherwise.
        '''
        if self.getProperty(index.DEBUG_LEVEL,printDebugMessage=False) >= int(secrecyLevel):
            print "{0}DEBUG({1}): {2}".format(self.makeSpaces(spaces),secrecyLevel,message)
            return True
        return False
    
    def query(self,query='',attributes=None,base=None):
        '''
        Executes an LDAP query.
        
        Args:
            query: the query string.
            attributes: A list of attributes that we wish to fetch.
            base: The distinguished name to base our search in.
            
        Returns:
            The list of results. References are omitted.
        '''
        handle = self.getProxyHandle()
        
        if not base:
            base = self.getProperty(index.BASE_DN)

        returnList = []

        self.printDebug("Executing LDAP search.",DEBUG_LEVEL_EXTREME)
        self.printDebug("    Filter: {0}".format(str(query)),DEBUG_LEVEL_EXTREME)
        self.printDebug("    Base: {0}".format(str(base)),DEBUG_LEVEL_EXTREME)
        
        try:        
            results = handle.search_s(base,ldap.SCOPE_SUBTREE,query,attributes)
        except:
            self.printDebug("BAD QUERY",DEBUG_LEVEL_EXTREME)
            traceback.print_exc(file=sys.stdout)
            # Return the empty list.
            return returnList
        for result in results:
            # Some LDAP servers include reference information in place of the attributes that we want to search for.
            # If this is the case, the distinguished name of the 'row' will be set to None.
            dn,attrs = result
            if dn:
                returnList.append(result)
        return returnList
    

    def resolveGroupDN(self,groupName,uidAttribute=False):
        '''
        Resolve a group DN based on the given index.
        
        Args:
            groupName: The group name we are trying to resolve.
            uidAttribute: The attribute that groupName can be found in.
        
        Returns:
            A string with the group's distinguished name if they have been resolved, False otherwise.
        '''  
        
        cacheCategory='resolvedGroups'
        cacheId = self.initCache(cacheCategory,False)
        
        if not uidAttribute:
            uidAttribute = self.getProperty(index.GROUP_UID_ATTRIBUTE)
        if groupName in self.cache[cacheCategory][cacheId]:
            self.printDebug("Using cached DN for '{0}'. Value: {1}".format(groupName,self.cache[cacheCategory][cacheId][groupName]),DEBUG_LEVEL_MAJOR)
            return self.cache[cacheCategory][cacheId][groupName]
        returnValue = self.resolveObjectDN(self.getProperty(index.GROUP_CLASS),uidAttribute,groupName,self.getGroupBaseDN())
    
        # Add to the list of resolved groups.
        self.cache[cacheCategory][cacheId][groupName] = returnValue
        
        if returnValue not in self.cache[cacheCategory][cacheId]:
            # May as well cache the reverse of this lookup as well.
            self.cache[cacheCategory][cacheId][returnValue] = groupName
        return returnValue
        
    def resolveGroupUID(self,groupDN,uidAttribute=False):
        ''' 
        Resolve a group's name from a given DN.
        
        Args:
            groupDN: The distinguished name of the group that we want to find the UID attribute for.
            uidAttribute: Attribute that we are searching for. Defaults to the value of GROUP_UID_ATTRIBUTE.
            
        Returns:
            If the UID was successfully resolved, returns the string.
            If the UID was not successfully resolved, return False.
        '''
        
        cacheCategory='resolvedGroups'
        cacheId = self.initCache(cacheCategory,False)
        
        if not uidAttribute:
            # No override provided.
            uidAttribute = self.getProperty(index.GROUP_UID_ATTRIBUTE)
        
        query = "(&(objectClass={0})({1}=*))".format(self.getProperty(index.GROUP_CLASS),self.getProperty(index.GROUP_UID_ATTRIBUTE))
        self.printDebug("Query for value of '{0}' for DN of '{1}': {2}".format(uidAttribute,groupDN,query), DEBUG_LEVEL_MAJOR)

        # Checking cached values.
        if groupDN in self.cache[cacheCategory][cacheId]: 
            self.printDebug("Using cached UID for '{0}'. Value: {1}".format(groupDN,self.cache[cacheCategory][cacheId][groupDN]),DEBUG_LEVEL_MAJOR)
            return self.cache[cacheCategory][cacheId][groupDN]
        
        result = self.query(query,[uidAttribute],groupDN)
        
        try:
            for i in result:
                # We only care about the first result. There should only be one, to boot.
                dn, attributes = i
                
                # Grabbing the UID attribute.
                # If the UID value is incorrect, the exception will happen here.
                returnValue = attributes[uidAttribute][0]
                
                self.cache[cacheCategory][cacheId][groupDN] = returnValue
                if returnValue not in self.cache[cacheCategory][cacheId]:
                    # May as well cache the reverse of this lookup as well.
                    self.cache[cacheCategory][cacheId][returnValue] = groupDN
                return returnValue
        except:
            # Unable to find the group ID. Cache this failure.
            
            self.cache[cacheCategory][cacheId][groupDN] = None
            return False
    
    def resolveObjectDN(self,objectClass,indexAttribute,objectName,base=None):
        '''
        Method to resolve an instance of a class.
        
        class: the objectClass that we want to resolve for.
        objectAttribute: the attribute that objectName can be found in.
        objectName: the group name we are trying to resolve.
        base: the search base.
        
        Returns:
            A string with the object's distinguished name if they have been resolved, False otherwise.
        '''
        if not base:
            base=self.getProperty(index.BASE_DN)
        query = '(&(objectClass={0})({1}={2}))'.format(objectClass,indexAttribute,objectName)
        self.printDebug("Resolving the DN of an item with the objectClass '{0}': {1}".format(objectClass,query),DEBUG_LEVEL_MAJOR)
        
        result = self.query(query,['distinguishedName'],base=base)
        if len(result) > 0:
            dn,attributes = result[0]
            if dn:
                return dn
            return False
    
    def resolveObjectUID(self,objectDN,objectIdentifier):
        '''
        Get the UID of an object. A pre-configured alias of getSingleAttribute()
        
        Args:
            objectDN: Distinguished Name to search in.
            objectIdentifier: the single-valued attribute representing an object's unique identifier.
        '''
        return self.getSingleAttribute(dn=objectDN,attribute=objectIdentifier)
    
    def resolveUserDN(self,userName,uidAttribute=False):
        '''
        Resolve a user DN based on the given index.
        
        Args:
            userName: The username we are trying to resolve.
            uidAttribute: The attribute that the userName can be found in.
        
        Returns:
            A string with the user's distinguished name if they have been resolved, False otherwise.
        '''
        
        cacheCategory='resolvedUsers'
        cacheId = self.initCache(cacheCategory,False)
        
        if not uidAttribute:
            uidAttribute = self.getProperty(index.USER_UID_ATTRIBUTE)
        if userName in self.cache[cacheCategory][cacheId]:
            self.printDebug("Using cached DN for '{0}'. Value: {1}".format(userName,self.cache[cacheCategory][cacheId][userName]),DEBUG_LEVEL_MAJOR)
            return self.cache[cacheCategory][cacheId][userName]
        returnValue = self.resolveObjectDN(self.getProperty(index.USER_CLASS),uidAttribute,userName,self.getUserBaseDN())
        
        self.cache[cacheCategory][cacheId][userName] = returnValue
        
        if returnValue not in self.cache[cacheCategory][cacheId]:
            # May as well cache the reverse of this lookup as well.
            self.cache[cacheCategory][cacheId][returnValue] = userName
        return returnValue

    def resolveUserUID(self,userDN,uidAttribute=False):
        ''' 
        Resolve a user's name from a given DN.
        
        Args:
            userDN: The distinguished name of the group that we want to find the UID attribute for.
            uidAttribute: Attribute that we are searching for. Defaults to the value of USER_UID_ATTRIBUTE.
            
        Returns:
            If the UID was successfully resolved, returns the string.
            If the UID was not successfully resolved, return False.
        '''
        cacheCategory='resolvedUsers'
        cacheId = self.initCache(cacheCategory,False)
        
        if not uidAttribute:
            # No override provided.
            uidAttribute = self.getProperty(index.USER_UID_ATTRIBUTE)
        
        query = "(&(objectClass={0})({1}=*))".format(self.getProperty(index.USER_CLASS),self.getProperty(index.USER_UID_ATTRIBUTE))
        self.printDebug("Query for value of '{0}' for DN of '{1}': {2}".format(uidAttribute,userDN,query), DEBUG_LEVEL_MAJOR)

        # Checking cached values.
        if userDN in self.cache[cacheCategory][cacheId]:
            self.printDebug("Using cached UID for '{0}'. Value: {1}".format(userDN,self.cache[cacheCategory][cacheId][userDN]),DEBUG_LEVEL_MAJOR)
            return self.cache[cacheCategory][cacheId][userDN]
        
        result = self.query(query,[uidAttribute],userDN)
        
        try:
            for i in result:
                # We only care about the first result. There should only be one, to boot.
                dn, attributes = i
                
                # Grabbing the UID attribute.
                # If the UID value is incorrect, the exception will happen here.
                returnValue = attributes[uidAttribute][0]
                
                self.cache[cacheCategory][cacheId][userDN] = returnValue
                # May as well cache the reverse of this lookup as well.
                if returnValue not in self.cache[cacheCategory][cacheId]:
                    self.cache[cacheCategory][cacheId][returnValue] = userDN
                return returnValue
        except:
            # Unable to find the user ID.
            self.cache[cacheCategory][cacheId][userDN] = None
            traceback.print_exc(file=sys.stdout)
            return None
    
    def setProperty(self,key,value):
        '''
        Set a single property.
        
        Args:
            key: The name of the property to update.
            value: New value to insert into key.
            
        Returns:
            None
        '''
        self.printDebug("Setting the '{0}' property to the value of '{1}' (Old value: '{2}')".format(key,value,self.getProperty(key)),self.DEBUG_LEVEL_MINOR)
        self.properties[key] = value
        
    
    def updateProperties(self,newProperties):
        '''
        Set multiple properties.
        
        Args:
            newProperties: a dictionary of property values.
            
        Returns:
            None
        '''
        self.properties.update(newProperties)
