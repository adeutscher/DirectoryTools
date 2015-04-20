
__version__ = 0.1

import base64,binascii,re,sys,traceback,ldap
from time import time
from datetime import datetime
import ConfigParser
import logging

import DirectoryToolsIndexes as index
import DirectoryToolsSchemas as schema
import DirectoryToolsExceptions as exceptions

DEBUG_LEVEL_NONE = 0
DEBUG_LEVEL_MINOR = 1
DEBUG_LEVEL_MAJOR = 2
DEBUG_LEVEL_EXTREME = 3

LOG_LEVEL_NONE = -1
LOG_LEVEL_NOTSET = 0
LOG_LEVEL_DEBUG = 10
LOG_LEVEL_INFO = 20
LOG_LEVEL_WARNING = 30
LOG_LEVEL_ERROR = 40
LOG_LEVEL_CRITICAL = 50

class DirectoryTools:
    """
    Class containing methods for querying an LDAP server.
    """
    
    ## Default properties.
    defaultProperties = {
        index.LOG_LEVEL:-1,
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
        index.DEFAULT_CACHE_CATEGORY:'general',
        index.DEFAULT_CACHE_ID:'general',
    }
    
    ## No debugging.
    DEBUG_LEVEL_NONE = 0
    ## Debug level 1
    DEBUG_LEVEL_MINOR = 1
    ## Debug level 2
    DEBUG_LEVEL_MAJOR = 2
    ## Debug level 3
    DEBUG_LEVEL_EXTREME = 3
    
    ## The name of the .INI file section that configuration entries are to be placed under.
    CONFIG_SECTION_HEADER='DirectoryTools'
    
    ## Handle used to search the directory server.
    proxyHandle = False
    
    ## Cache for reducing the number of queries that need to be run, especially common ones like resolving a DN.
    cache = {}
    

    def __init__(self,properties=False,template='openldap',configFile=False,enableStdOut=False):
        '''
        Initializes the DirectoryTools object.
        
        Args:
            properties: Dictionary of properties. Can be updated through setProperties or updateProperties.
            template: String describing a template schema that defines common properties given LDAP server implementation. If the schema is not found, then the program will exit.
            configFile: Optional path to a configuration file.
            enableStdOut: Boolean flag to enable basic output through stdOut. For more advanced output methods, add extra handlers from the logging module to `self.logger`.
        '''
        
        ## Logging object to print debug output.
        self.logger = logging.getLogger()
        self.logger.handlers = []
        self.logger.setLevel(logging.NOTSET)
        if enableStdOut:
            self.enableStdOut()
        else:
            self.logger.addHandler(NullHandler())
        
        ## Dictionary of property values.
        self.properties = self.defaultProperties.copy()
        
        if configFile:
            try:
                self.loadConfigFile(configFile)
            except:
                print "Unable to load configuration file '{0}'".format(configFile);
                exit(1);
        
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
        
        self.printDebug("Attempting to authenticate user '{0}'.".format(userName), LOG_LEVEL_WARNING)
        self.printDebug("INFO", LOG_LEVEL_INFO)
        self.printDebug("DEBUG", LOG_LEVEL_DEBUG)

        if userNameIsDN:
            # The username has been provided in DN form.
            # Don't need to bother resolving or confirming.
            # Authentication will throw the same error whether we have a non-existent user or a bad password.
            userDN = userName
        else:
            userDN = self.resolveUserDN(userName)
            
            if not userDN:
                # Don't bother authenticating if the user doesn't exist.
                self.printDebug("User '{0}' cannot be found.".format(userName), LOG_LEVEL_WARNING)
                return False
        
        handle = self.getHandle()
        
        try:
            # Attempt to do a simple bind. If anything goes wrong, we'll be thrown to our 'except'.
            result = handle.simple_bind_s(userDN,password)
            self.printDebug("Successfully authenticated user '{0}'.".format(userName), LOG_LEVEL_WARNING)
            return True
        except ldap.LDAPError, e:
            
            logLevel = self.getProperty(index.LOG_LEVEL)
            
            if logLevel != LOG_LEVEL_NONE and logLevel >= LOG_LEVEL_CRITICAL:
                traceback.print_exc(file=sys.stdout)
            self.printDebug("LDAP Error: {0}".format(e),LOG_LEVEL_CRITICAL)
            
            return False
            
    def enableStdOut(self):
        '''
        DirectoryTools uses Python's logging module for debug output. By default, printing to stdout is not enabled.
        
        This method sets up a standard handler for printing to stdout for those who aren't familiar with the logging module.
        '''
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter(fmt="%(levelname)s %(message)s"))
        self.logger.addHandler(sh)
            
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
        if len(self.getProperty(index.GROUP_RDN)):
            return "{0},{1}".format(self.getProperty(index.GROUP_RDN),self.getProperty(index.BASE_DN))
        else:
            return self.getProperty(index.BASE_DN)
          

    def getGroupMembers(self,groupName,groupNameIsDN=False,returnMembersAsDN=False,objectClassFilter=None,uidAttribute='uid',depth=0,cacheId=False):
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
        if not cacheId:
            cacheTuple = self.initCache(cacheCategory,cacheId,generateCacheId=True)
        else:
            cacheTuple = self.initCache(cacheCategory,cacheId)
            
        cacheCategory,cacheId = cacheTuple
        
        if not groupNameIsDN:
            # We want to confirm that the group exists and get its Distinguished Name.
            groupDN = self.resolveGroupDN(groupName,self.getProperty(index.GROUP_UID_ATTRIBUTE))
            if not groupDN:
                self.printDebug("Could not locate group: {0}".format(groupName),LOG_LEVEL_ERROR)
                return []
        else:
            # Group name is already a DN.
            groupDN = groupName

        # Making sure that we have not already searched this group.
        if groupName not in self.cache[cacheCategory][cacheId]:
                self.cache[cacheCategory][cacheId][groupName] = 1
                self.printDebug("Getting members of group '{0}'.".format(groupName),LOG_LEVEL_INFO)
        else:
            self.printDebug("Skipping already searched group: {0}".format(groupName), LOG_LEVEL_DEBUG)
            return []
        
        memberList = []
        
        if depth > self.getProperty(index.MAX_DEPTH) and not self.getProperty(index.MAX_DEPTH) < 0:
            raise exceptions.ExceededMaxDepthException(depth=depth,resultItem=memberList)
            #self.printDebug("Exceeded max depth of {1}.".format(self.getProperty(index.MAX_DEPTH)), DEBUG_LEVEL_MINOR)
            #return memberList

        # Compile query for finding group.
        #query = '(&(objectClass=%s)(%s=%s))' % tuple([self.getProperty(index.GROUP_CLASS),groupIdentifier,groupName])
        #self.printDebug("Searching for member users in group '%s'. Query: %s: " % tuple([groupName,query]),DEBUG_LEVEL_MAJOR)
        query = '(%s=%s)'
        self.printDebug("Searching for members in group '{0}'.".format(groupName),LOG_LEVEL_INFO)

        members = self.getMultiAttribute(groupDN,self.getProperty(index.MEMBER_ATTRIBUTE))
        for member in members:
                
            if self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN):
                # Distinguished names may be nested groups.
                # We need to double check whether or not this DN is indeed a group.
                
                
                if not objectClassFilter:
                    self.printDebug("Adding object '{0}' to list (No Filter).".format(member), LOG_LEVEL_DEBUG)
                    memberList.append(member)
                elif objectClassFilter and self.isObjectOfClass(member,objectClassFilter):
                    # Either we are not filtering by group, or the object at this DN is of the class we want to filter by.
                    self.printDebug("Adding object '{0}' to list (Passed Filter).".format(member), LOG_LEVEL_DEBUG)
                    memberList.append(member)
                
                if self.getProperty(index.NESTED_GROUPS) and (not (depth >= self.getProperty(index.MAX_DEPTH)) and (not self.getProperty(index.MAX_DEPTH) < 0)) and self.isObjectGroup(member):
                    # If this section is being executed we have confirmed three things: 
                    # * We want to search in nested groups.
                    # * We have not yet exceeded the maximum search depth.
                    # * The object is actually a group (kind of important!).
                    
                    self.printDebug("Searching within nested group '{0}'".format(member), LOG_LEVEL_INFO)
                    
                    try:
                        memberList.extend(
                            self.getGroupMembers(groupName=member,groupNameIsDN=True,returnMembersAsDN=True,objectClassFilter=objectClassFilter,uidAttribute=uidAttribute,depth=(depth+1))
                        )
                    except exceptions.ExceededMaxDepthException, e:
                        memberList.extend(e.resultItem)

            else:
                # POSIX-style members can be trusted to be the type they are labeled as.
                # POSIX-style members will not be nested groups.
                memberList.append(member)
        
        if depth > 0:
            # We are not in the first call of the function. Return the list as we have it right now to be processed at the top level.
            return memberList
        
        # Begin top-level processing. The following code should only be processed if we're in the top call of this method.
            
        self.printDebug("Finished gathering members of group '{0}'. Formatting results.".format(groupName),LOG_LEVEL_DEBUG)
        
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
        try:
            protocol = ('ldap','ldaps')[self.getProperty(index.USE_SSL)]
            
            uri = '{0}://{1}:{2}'.format(protocol,self.getProperty(index.SERVER_ADDRESS),self.getProperty(index.SERVER_PORT))
            self.printDebug("Connection URI: {0}".format(uri),LOG_LEVEL_DEBUG)
            
            connectionProperties = self.getProperty(index.LDAP_PROPERTIES)
            
            connection = ldap.initialize(uri)
            
            for i in connectionProperties:
                self.printDebug('Applying connection property \'{0}\' to connection. Value: \'{1}\''.format(i,connectionProperties[i]),LOG_LEVEL_DEBUG)
                connection.set_option(i,connectionProperties[i])
            
            return connection
        except Exception, e:
            raise exceptions.ConnectionFailedException(originalException=e)

    def getMultiAttribute(self,dn,attribute):
        '''
        Get a single multi-valued attribute from the server. Alias for getObjectAttribute.
        
        Args:
            dn: Distinguished name to get the attribute from.
            attribute: Attribute to search for.
        '''
        return self.getObjectAttribute(dn=dn,attribute=attribute)

    def getObjectAttributes(self,dn,attributes):
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

    def getProperty(self,key,useDefault=True,defaultOverride=None,printDebugMessage=True):
        ''' 
        Gets a property value.
        
        Args:
            key: Name of the property to retrieve. Recommended to go through the values in DirectoryToolsIndexes.
            useDefault: a boolean flag. If set to True, the method will attempt to look in self.defaultProperties before throwing an exception.
            defaultOverride: Value to provide as a default if the value is not found in self.debugProperties. This takes precedence over a value in self.defaultProperties.
            printDebugMessage: Since printDebug relies on this method, this is our current solution for avoiding an endless loop. Needs improvement.
            
        Returns:
            The value of a key out of either the properties or defaults dictionary.
        '''
        
        try:
            if printDebugMessage:
                self.printDebug("Fetching property '{0}'".format(key),LOG_LEVEL_DEBUG)
            return self.properties[key]
        except KeyError, e:
            self.printDebug("Could not find key '{0}' in properties.".format(key),LOG_LEVEL_DEBUG)
            if defaultOverride is not None:
                self.printDebug("Using override default: {0}".format(defaultOverride),LOG_LEVEL_DEBUG)
                return defaultOverride
            elif useDefault:
                try:
                    self.printDebug("Searching default properties...",self.LOG_LEVEL_DEBUG)
                    return self.defaultProperties[key]
                except KeyError, e:
                    # The property *still* wasn't found in the default properties.
                    self.printDebug("Could not find key '{0}' in default properties".format(key),LOG_LEVEL_DEBUG)
                    raise exceptions.PropertyNotFoundException(key=key,triedDefault=True)
            else:
                # No override, and not using the default.
                raise exceptions.PropertyNotFoundException(key=key)

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
            except ldap.LDAPError, e:
                # This exception is thrown when the call to connection.simple_bind_s fails.
                # print "Proxy connection failed."

                if e.args[0]['desc'] == 'Invalid credentials':
                    # The error happened because the proxy connection was given the wrong credentials.
                    raise exceptions.ProxyAuthFailedException(originalException=e)
                else:
                    raise exceptions.ProxyFailedException(originalException=e)
            
            self.printDebug("Successfully created proxy handle.",LOG_LEVEL_DEBUG)
        else:
            self.printDebug("Returning cached proxy handle.",LOG_LEVEL_DEBUG)
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
        if len(self.getProperty(index.USER_RDN)):
            return "{0},{1}".format(self.getProperty(index.USER_RDN),self.getProperty(index.BASE_DN))
        else:
            return self.getProperty(index.BASE_DN)

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


    def initCache(self,category='general',cacheId=None,generateCacheId=False):
        '''
        Ensures that a cache is initialized. A specific cache will be a dictionary indexed by cacheId, which is nested in a cache for categories.
        
        Args:
            category: The general category of the cache. For example, 'searchedGroups', 'resolvedDNs'. If left at none, the default category will be used according to the DEFAULT_CACHE_CATEGORY property.
            cacheId: Specifies the cache ID. If a value is given, the cacheId will be set to this value. If left at default of None, the default cache will be used according to the DEFAULT_CACHE_ID property.
            generateCacheId: If set to True, a cache ID will be generated using a UNIX timestamp and the current microseconds. Setting this value to True will take precedence over the value of cacheId.
        Returns:
            A tuple. The first value will cacheCategory that was used, and the second value will be the cacheId being used.
        '''
        
        # Make sure that the cache object is initialized.   
        try:
            if type(self.cache) is not dict:
                self.cache = {}
        except NameError:
            self.cache = {}
        
        # Check if we need to use the default category.
        if not category:
            category = self.getProperty(index.DEFAULT_CACHE_CATEGORY)
        
        # Confirm the cache ID that we'll be working with.
        if generateCacheId:
            # Using a UNIX timestamp in milliseconds to get my cache Id.
            timeObj = datetime.now()
            cacheId =  str(time()) + str(timeObj.microsecond)
        elif cacheId:
            # We have been given a cache Id. If it doesn't already exist, we need to make it.
            
            # Make sure that we are working with a string.
            cacheId = str(cacheId)
        else:
            # Not using a specific cache Id. Defaulting to general.
            cacheId = self.getProperty(index.DEFAULT_CACHE_ID)
            
        # Make sure that the category is initialized.
        # Do not overwrite an existing dictionary, but correct any non-dictionary that has snuck in.
        if category not in self.cache or type(self.cache[category]) is not dict:
            self.printDebug("Creating cache category '{0}'".format(category),LOG_LEVEL_DEBUG)
            self.cache[category] = {}
        else:
            self.printDebug("Cache category '{0}' already exists.".format(category),LOG_LEVEL_DEBUG)

        # Make sure that the cache ID of the category is initialized.
        # Do not overwrite an existing dictionary, but correct any non-dictionary that has snuck in.
        if cacheId not in self.cache[category] or type(self.cache[category][cacheId]) is not dict:
            self.printDebug("Creating '{0}' cache with Id of '{1}'".format(category,cacheId),LOG_LEVEL_DEBUG)
            self.cache[category][cacheId] = {}
        else:
            self.printDebug("'{0}' cache with id of '{1}' already exists.".format(category,cacheId),LOG_LEVEL_DEBUG)
        
        # Return the cache id that we are using. A recursive function must use the same cache Id.
        return tuple([category,cacheId])

    def loadConfigFile(self,configFilePath):
        '''
        Loads the contents of a configuration file into self.properties.
        
        args:
            configFilePath: Path to an ini-style configuration file. The contents of the [DirectoryTools] section are loaded into self.properties. All other sections are ignored.
        '''
        
        parser = ConfigParser.ConfigParser()
        parser.read(configFilePath)
        
        if self.CONFIG_SECTION_HEADER in parser.sections():
            for option in parser.options(self.CONFIG_SECTION_HEADER):
                # Get our value and strip out quotes.
                v = re.sub(r'^[\'\"]*|[\'\"]*$','',parser.get(self.CONFIG_SECTION_HEADER,option))
                if v.lower() in ['yes','true',"1"]:
                    # Boolean true.
                    self.setProperty(option,True)
                elif v.lower() in ['no','false',"0","nope"]:
                    # Boolean false.
                    # Added "nope" for humour.
                    self.setProperty(option,False)
                elif re.match(r'^[1-90]*$',v):
                    # Is an integer.
                    self.setProperty(option,int(v))
                else:
                    # Standard. Is a string.
                    self.setProperty(option,v)
    
    def isObjectGroup(self,groupDN):
        '''
        Confirms that the specified object is a group by virtue of having an objectClass value of the GROUP_CLASS property. Pre-configured alias of isObjectOfClass().
        
        Args:
            groupDN: The DN of the object that we are confirming as a group.
            
        Returns:
            True if the object is a member of a group, false otherwise.
        '''
        return self.isObjectOfClass(objectDN=groupDN,objectClass=self.getProperty(index.GROUP_CLASS))

    def isObjectInGroup(self,objectName,groupName,objectNameIsDN=False,groupNameIsDN=False,objectIdentifier=False,objectClass=False,objectBase=False,depth=0,cacheId=False):
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
        if not cacheId:
            cacheTuple = self.initCache(cacheCategory,cacheId,generateCacheId=True)
        else:
            cacheTuple = self.initCache(cacheCategory,cacheId)
            
        cacheCategory,cacheId = cacheTuple
        
        self.printDebug("Searching for user '{0}' in group '{1}'".format(objectName,groupName),LOG_LEVEL_INFO)
        
        if groupName in self.cache[cacheCategory][cacheId]:
            # We have already searched in this group.
            self.printDebug("Skipping group '{0}'. Already searched.".format(groupName),LOG_LEVEL_INFO)
            return False
        self.cache[cacheCategory][cacheId][groupName] = 1
        
        if int(depth) > self.getProperty(index.MAX_DEPTH) and not self.getProperty(index.MAX_DEPTH) < 0:
            raise exceptions.ExceededMaxDepthException(depth=depth,resultItem=False)
        
        # We need the DN of the group to get its attributes.
        if groupNameIsDN:
            # No need to resolve, groupName provided as DN.
            groupDN = groupName
        else:
            # Group DN needs to be resolved, UID was provided.
            groupDN = self.resolveGroupDN(groupName)
            if not groupDN:
                # Can't find group, no point in continuing.
                self.printDebug("Cannot locate group '{0}' in order to search for member '{1}' within it. Returning False.".format(groupName,objectName),LOG_LEVEL_ERROR)
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
                self.printDebug("Verified object '{0}' as a member of group '{1}'".format(objectName,groupName),LOG_LEVEL_INFO)
                return True
        
        else:
            # Groups in the LDAP server stores its member properties as distinguished names.
            
            # self.getProperty(index.MEMBER_ATTRIBUTE_IS_DN) is true
            # We cannot count on the objects in this group to only be users.
            for member in members:
                # Cycle through group results.
                
                if member == searchName:
                    self.printDebug("Verified object '{0}' as a member of group '{1}'".format(objectName,groupName),LOG_LEVEL_INFO)
                    return True
                elif self.getProperty(index.NESTED_GROUPS) and self.isObjectGroup(member):
                    # We have stated that we want to search through nested groups.
                    # The item is a group, and the object is a member of it.
                    
                    # But first, we want to search through other direct memberships
                    # to make sure that the desired property is not here.
                    self.printDebug("Observed group '{0}'. Will search through it if no direct matches are found in this group.".format(member),LOG_LEVEL_INFO)
                    nestedGroupList.append(member)
                else:
                    # If the if statement is not triggered, then the object is a object.
                    # Any object type other than the group is irrelevant, placing the else statement for the sake of verbosity.
                    self.printDebug("Observed non-matching object '{0}'".format(member),LOG_LEVEL_DEBUG)
        
            # We have completed cycling through the memberList variable for users, and have not found a matching user.
            for nestedGroup in nestedGroupList:
                try:
                    if self.isObjectInGroup(objectName,self.resolveGroupUID(nestedGroup),objectNameIsDN=objectNameIsDN,groupNameIsDN=groupNameIsDN,objectIdentifier=objectIdentifier,objectClass=objectClass,objectBase=objectBase,depth=(depth+1),cacheId=cacheId):
                        return True
                except exceptions.ExceededMaxDepthException, e:
                    # Re-raising the exception. I have the suspicion that if I didn't I'd have many superfluous lines in stack traces.
                    # Acknowledging that this means we won't be searching the other items in the list of groups. They would all be of (depth+1), so they would all raise the exception again
                    raise exceptions.ExceededMaxDepthException(message=e.message,depth=e.depth,resultItem=e.resultItem)
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
        cacheTuple = self.initCache(cacheCategory,objectClass)
        cacheCategory,cacheId = cacheTuple
        
        self.printDebug("Checking whether the object at '{0}' is of class '{1}'".format(objectDN,cacheId),LOG_LEVEL_INFO)
        
        # Attempt to find the object in the cache.
        if objectDN in self.cache[cacheCategory][cacheId]:
            if self.cache[cacheCategory][cacheId][objectDN]:
                self.printDebug("Verified object as being of class '{0}' using cache.".format(cacheId),LOG_LEVEL_DEBUG)
                return True
            else:
                self.printDebug("Cache reports that we could not verify object as being of class '{0}'.".format(cacheId),LOG_LEVEL_DEBUG)
                return False
            
        classes = self.getMultiAttribute(objectDN,'objectClass')
        if objectClass in classes:
            self.cache[cacheCategory][cacheId][objectDN] = True
            self.printDebug("Verified object as being of class '{0}' using cache.".format(cacheId),LOG_LEVEL_DEBUG)
            return True
        else:
            self.cache[cacheCategory][cacheId][objectDN] = False
            self.printDebug("Cache reports that we could not verify object as being of class '{0}'.".format(cacheId),LOG_LEVEL_DEBUG)
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

    def printDebug(self,message,secrecyLevel=100):
        '''
        Prints a debug message.
        
        The message will only be printed if the debug level is equal to or greater than the clearance level.
        
        Args:
            message: The message to print.
            secrecyLevel: The authorization required to print. The LOG_LEVEL property must be equal to or greater than this secrecy level to print the message.
            
        Returns:
            True if the message was sent, False otherwise.
        '''
        
        logLevel = self.getProperty(index.LOG_LEVEL,printDebugMessage=False)
        if logLevel != LOG_LEVEL_NONE and logLevel >= int(secrecyLevel):
            self.logger.log(secrecyLevel,message)
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

        self.printDebug("Executing LDAP search.",LOG_LEVEL_DEBUG)
        self.printDebug("    Filter: {0}".format(str(query)),LOG_LEVEL_DEBUG)
        self.printDebug("    Base: {0}".format(str(base)),LOG_LEVEL_DEBUG)
        
        try:        
            results = handle.search_s(base,ldap.SCOPE_SUBTREE,query,attributes)
        except Exception, e:
            # A bad query becomes a much more important thing to log.
            self.printDebug("BAD QUERY: {0}".format(str(query)),LOG_LEVEL_CRITICAL)
            raise exceptions.BadQueryException(originalException=e)
        
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
        cacheTuple = self.initCache(cacheCategory)
        cacheCategory,cacheId = cacheTuple
        
        if not uidAttribute:
            uidAttribute = self.getProperty(index.GROUP_UID_ATTRIBUTE)
        if groupName in self.cache[cacheCategory][cacheId]:
            self.printDebug("Using cached DN for '{0}'. Value: {1}".format(groupName,self.cache[cacheCategory][cacheId][groupName]),LOG_LEVEL_DEBUG)
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
        cacheTuple = self.initCache(cacheCategory)
        cacheCategory,cacheId = cacheTuple
        
        
        if not uidAttribute:
            # No override provided.
            uidAttribute = self.getProperty(index.GROUP_UID_ATTRIBUTE)
        
        query = "(&(objectClass={0})({1}=*))".format(self.getProperty(index.GROUP_CLASS),self.getProperty(index.GROUP_UID_ATTRIBUTE))
        self.printDebug("Query for value of '{0}' for DN of '{1}': {2}".format(uidAttribute,groupDN,query), LOG_LEVEL_DEBUG)

        # Checking cached values.
        if groupDN in self.cache[cacheCategory][cacheId]: 
            self.printDebug("Using cached UID for '{0}'. Value: {1}".format(groupDN,self.cache[cacheCategory][cacheId][groupDN]),LOG_LEVEL_DEBUG)
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
        self.printDebug("Resolving the DN of an item with the objectClass '{0}': {1}".format(objectClass,query),LOG_LEVEL_DEBUG)
        
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
        cacheTuple = self.initCache(cacheCategory)
        cacheCategory,cacheId = cacheTuple
        
        if not uidAttribute:
            uidAttribute = self.getProperty(index.USER_UID_ATTRIBUTE)
        if userName in self.cache[cacheCategory][cacheId]:
            self.printDebug("Using cached DN for '{0}'. Value: {1}".format(userName,self.cache[cacheCategory][cacheId][userName]),LOG_LEVEL_DEBUG)
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
        cacheTuple = self.initCache(cacheCategory)
        cacheCategory,cacheId = cacheTuple
        
        if not uidAttribute:
            # No override provided.
            uidAttribute = self.getProperty(index.USER_UID_ATTRIBUTE)
        
        query = "(&(objectClass={0})({1}=*))".format(self.getProperty(index.USER_CLASS),self.getProperty(index.USER_UID_ATTRIBUTE))
        self.printDebug("Query for value of '{0}' for DN of '{1}': {2}".format(uidAttribute,userDN,query), LOG_LEVEL_DEBUG)

        # Checking cached values.
        if userDN in self.cache[cacheCategory][cacheId]:
            self.printDebug("Using cached UID for '{0}'. Value: {1}".format(userDN,self.cache[cacheCategory][cacheId][userDN]),LOG_LEVEL_DEBUG)
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
        
        if key in self.properties:
            self.printDebug("Setting the '{0}' property to the value of '{1}' (Old value: '{2}')".format(key,value,self.getProperty(key)),LOG_LEVEL_DEBUG)
        else:
            self.printDebug("Setting the '{0}' property to the value of '{1}'".format(key,value),LOG_LEVEL_DEBUG)
        
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

class Utilities:
    '''
    Contains various utility methods to support DirectoryTools methods.
    '''

    def decodeMicrosoftSid(self,encodedString):
        '''
        Decode a Microsoft SID.

        Args:
            encodedString: Base64-encoded string of binary data, as one might find when directly querying an LDAP server.

        Returns:
            A string containing a translated SID value.
        '''
        hexString = binascii.b2a_hex(binascii.a2b_base64(encodedString))
        numberList = []
        stringList = []

        # Process the revision number.
        numberList.append(int(hexString[0:2],16))

        # Decoding SID Format r1.
        if numberList[0] == 1:
            # Process the sub-ID count.
            numberList.append(int(hexString[2:4],16))
            # Process Identifier Authority.
            identifierAuthority = int(hexString[4:16],16)
            i = 16
            while i < len(hexString):
                numberList.append(self.decodeMicrosoftSubAuthority(hexString[i:i+8]))
                i+=8

            # Convert list of numbers to list of strings.
            for s in numberList:
                stringList.append(str(s))

            return str.format('S-{0}','-'.join(stringList))

    def decodeMicrosoftSubAuthority(self,inputString):
        '''
        Active Directory sub authorities are stored as unsigned 32-bit integers that are stored in reverse byte order (Big Endian).

        This method decodes the hex representation of a sub authority and gets its integer value.

        Args:
            inputString: Hex representation of a sub-authority. tored as unsigned 32-bit integers that are stored in reverse byte order (Big Endian)

        Returns:
            An integer containing the value stored in an Active Directory sub authority.
        '''
        s = []
        i = 0
        while i < len(inputString):
            s.append(int(inputString[i:i+2],16))
            i+=2
        l=[]
        l.append(int(s[0]))
        l.append(int(s[1]) * int(pow(16,2)))
        l.append(int(s[2]) * int(pow(16,4)))
        l.append(int(s[3]) * int(pow(16,6)))
        return sum(l)

    def encodeMicrosoftSid(self,sid,authority=5):
        '''
        Encodes a Microsoft SID.

        Args:
            sid: Microsoft SID in (near) human-readable form
            authority: Identifier authority used to create the object. I'm not terribly familiar with this value, but I do know that it is not stored in the human-readable SID.

        Returns:
            A base64-encoded string of binary data, as one might find when directly querying an LDAP server.
        '''
        componentList = sid.split('-')

        # Convert revision number to one hexidecimal digit in string form.
        revisionNumber = re.sub(r'^0x','',hex(int(componentList[1],10))).rjust(2,'0')

        # Decoding SID Format r1.
        if int(componentList[1],10) == 1:
            # Convert the Sub-Id count to one hexidecimal digit in string form.
            subIdCount = re.sub(r'^0x','',hex(int(componentList[2],10))).rjust(2,'0')

            # Convert the identifier authority to one hexidecimal digit in string form.
            identifierAuthority = re.sub(r'^0x','',hex(authority)).rjust(12,'0')

            # Manage remaining sub-ids. First subId is always index 3 of our broken-down SID.
            subIdIndex = 3
            subIdList = []
            while subIdIndex < len(componentList):
                subIdList.append(self.encodeMicrosoftSubAuthority(componentList[subIdIndex]))
                subIdIndex+=1

            # Combine values into one hex string.
            sidHexString = "{0}{1}{2}{3}".format(revisionNumber,subIdCount,identifierAuthority,"".join(subIdList))

            # Encode the hex string as a string of binary data that has been base64-encoded.
            encodedSidHexString = binascii.b2a_base64(binascii.a2b_hex((sidHexString)))

            # Encoded string has a newline tacked onto it. No idea why. Fixing and returning.
            return re.sub(r'\r*\n*','',encodedSidHexString)

    def encodeMicrosoftSubAuthority(self,inputString):
        '''
        Active Directory sub authorities are stored as unsigned 32-bit integers that are stored in reverse byte order (Big Endian). This method encodes the integer value of a sub authority to get its hex value.

        Args:
            inputString: String containing the integer value of a Microsoft sub authority.

        Returns:
            An string containing the hex representation of a sub-authority. Stored as unsigned 32-bit integers that are stored in reverse byte order (Big Endian).
        '''
        hexString = re.sub(r'^0x','',hex(int(inputString,10))).rjust(8,'0')
        reverseHexString = ''
        i = len(hexString)
        while i > 0:
            reverseHexString += hexString[i-2:i]
            i-=2
        return reverseHexString

    def getNTTimestampFromUnix(self,unixDate):
        '''
        Convert a UNIX timestamp to an NT timestamp.

        NT Timestamps are used in the following LDAP implementations (list will be updated as I confirm more implementations)
            - Active Directory

        Args:
            unixDate: Number representing a UNIX timestamp.

        Returns:
            An NT timestamp that can be used in queries against Active Directory.
        '''
        
        return int((unixDate + 11644473600) * 10000000)
    
    def getUnixTimestampDiff(self,unixDateA,unixDateB):
        '''
        Check the difference between two UNIX timestamps. Super-lazy method.
        
        Args:
            unixDateA: A UNIX timestamp.
            unixDateB: A UNIX timestamp.
            
        Returns:
            The number of seconds between two timestamps.
        '''
        
        return int(abs(a - b))
        
    def getUnixTimestampFromNT(self,ntDate):
        '''
        Convert an NT timestamp to a UNIX timestamp.
        
        Args:
            ntDate: String representing an NT timestamp.
            
        Returns:
            A UNIX timestamp.
        '''
        
        return int(((ad / 10000000) - 11644473600))
        
    def getIso8601FromUnix(self,unixDate):
        '''
        Convert a UNIX timestamp to a more human-friendly ISO8601 format.
        
        See also: http://xkcd.com/1179/
        
        Args:
            unixDate: A UNIX timestamp
            
        Returns:
            String of the time in ISO 8601 format.
        '''
        t = datetime.datetime.fromtimestamp(unixDate)
        return t.strftime('%Y-%m-%d')

    def getActiveDirectoryPassword(self,password):
        '''
        Take a password and put it into a format that is used for submitting Active Directory passwords.
        
        Note that the password still needs to adhere to the domain's password policy.
        
        Args:
            password: Password to encode.
        
        Returns:
            A base 64-encoded unicode string.
        '''
        
        unicodePass = unicode('\"' + password + '\"', 'iso-8859-1')
        passwordValue = unicodePass.encode('utf-16-le')
        encodedPassword = base64.b64encode(passwordValue)
        
        return encodedPassword
    
class UserAccountControlManager:
    '''
    Adds up flag values for Active Directory's UserAccountControl attribute.
    
    Built off of the content of http://support.microsoft.com/kb/305144
    '''
    
    # awk '{print "## "$0"\nUAC_KEY_"$1" = \""$1"\"^C' templdap
    
    ## SCRIPT - The logon script will be run.
    UAC_KEY_SCRIPT = "SCRIPT"
    ## ACCOUNTDISABLE - The user account is disabled.
    UAC_KEY_ACCOUNTDISABLE = "ACCOUNTDISABLE"
    ## HOMEDIR_REQUIRED - The home folder is required.
    UAC_KEY_HOMEDIR_REQUIRED = "HOMEDIR_REQUIRED"
    ## LOCKOUT - Account is locked out.
    UAC_KEY_LOCKOUT = "LOCKOUT"
    ## PASSWD_NOTREQD - No password is required.
    UAC_KEY_PASSWD_NOTREQD = "PASSWD_NOTREQD"
    ## PASSWD_CANT_CHANGE - The user cannot change the password. This is a permission on the user's object. For information about how to programmatically set this permission, visit the following Web site: http://msdn2.microsoft.com/en-us/library/aa746398.aspx
    UAC_KEY_PASSWD_CANT_CHANGE = "PASSWD_CANT_CHANGE"
    ## ENCRYPTED_TEXT_PWD_ALLOWED - Unknown. Need to research.
    UAC_KEY_ENCRYPTED_TEXT_PWD_ALLOWED = "ENCRYPTED_TEXT_PWD_ALLOWED"
    ## ENCRYPTED_TEXT_PASSWORD_ALLOWED - The user can send an encrypted password.
    UAC_KEY_ENCRYPTED_TEXT_PASSWORD_ALLOWED = "ENCRYPTED_TEXT_PASSWORD_ALLOWED"
    ## TEMP_DUPLICATE_ACCOUNT - This is an account for users whose primary account is in another domain. This account provides user access to this domain, but not to any domain that trusts this domain. This is sometimes referred to as a local user account.
    UAC_KEY_TEMP_DUPLICATE_ACCOUNT = "TEMP_DUPLICATE_ACCOUNT"
    ## NORMAL_ACCOUNT - This is a default account type that represents a typical user.
    UAC_KEY_NORMAL_ACCOUNT = "NORMAL_ACCOUNT"
    ## INTERDOMAIN_TRUST_ACCOUNT - This is a permit to trust an account for a system domain that trusts other domains.
    UAC_KEY_INTERDOMAIN_TRUST_ACCOUNT = "INTERDOMAIN_TRUST_ACCOUNT"
    ## WORKSTATION_TRUST_ACCOUNT - This is a computer account for a computer that is running Microsoft Windows NT 4.0 Workstation, Microsoft Windows NT 4.0 Server, Microsoft Windows 2000 Professional, or Windows 2000 Server and is a member of this domain.
    UAC_KEY_WORKSTATION_TRUST_ACCOUNT = "WORKSTATION_TRUST_ACCOUNT"
    ## SERVER_TRUST_ACCOUNT - This is a computer account for a domain controller that is a member of this domain.
    UAC_KEY_SERVER_TRUST_ACCOUNT = "SERVER_TRUST_ACCOUNT"
    ## DONT_EXPIRE_PASSWD - Represents the password, which should never expire on the account.
    UAC_KEY_DONT_EXPIRE_PASSWORD = "DONT_EXPIRE_PASSWD"
    ## MNS_LOGON_ACCOUNT - This is an MNS logon account.
    UAC_KEY_MNS_LOGON_ACCOUNT = "MNS_LOGON_ACCOUNT"
    ## SMARTCARD_REQUIRED - When this flag is set, it forces the user to log on by using a smart card.
    UAC_KEY_SMARTCARD_REQUIRED = "SMARTCARD_REQUIRED"
    ## TRUSTED_FOR_DELEGATION - When this flag is set, the service account (the user or computer account) under which a service runs is trusted for Kerberos delegation. Any such service can impersonate a client requesting the service. To enable a service for Kerberos delegation, you must set this flag on the userAccountControl property of the service account.
    UAC_KEY_TRUSTED_FOR_DELEGATION = "TRUSTED_FOR_DELEGATION"
    ## NOT_DELEGATED - When this flag is set, the security context of the user is not delegated to a service even if the service account is set as trusted for Kerberos delegation.
    UAC_KEY_NOT_DELEGATED = "NOT_DELEGATED"
    ## USE_DES_KEY_ONLY - (Windows 2000/Windows Server 2003) Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
    UAC_KEY_USE_DES_KEY_ONLY = "USE_DES_KEY_ONLY"
    ## DONT_REQUIRE_PREAUTH - (Windows 2000/Windows Server 2003) This account does not require Kerberos pre-authentication for logging on.
    UAC_KEY_DONT_REQUIRE_PREAUTH = "DONT_REQUIRE_PREAUTH"
    ## PASSWORD_EXPIRED - (Windows 2000/Windows Server 2003) The user's password has expired.
    UAC_KEY_PASSWORD_EXPIRED = "PASSWORD_EXPIRED"
    ## TRUSTED_TO_AUTH_FOR_DELEGATION - (Windows 2000/Windows Server 2003) The account is enabled for delegation. This is a security-sensitive setting. Accounts that have this option enabled should be tightly controlled. This setting lets a service that runs under the account assume a client's identity and authenticate as that user to other remote servers on the network. 
    UAC_KEY_TRUSTED_TO_AUTH_FOR_DELEGATION = "TRUSTED_TO_AUTH_FOR_DELEGATION"
    ## PARTIAL_SECRETS_ACCOUNT - (Windows Server 2008/Windows Server 2008 R2) The account is a read-only domain controller (RODC). This is a security-sensitive setting. Removing this setting from an RODC compromises security on that server.
    UAC_KEY_PARTIAL_SECRETS_ACCOUNT = "PARTIAL_SECRETS_ACCOUNT"
    
    def __init__(self):
        '''
        Initializes the dictionary of stored values, and preps the list of activated values.
        '''
        
        ## Dictionary of decimal values for the UAC properties:
        self.uacFlagKeyValues = {
            self.UAC_KEY_SCRIPT : 1,
            self.UAC_KEY_ACCOUNTDISABLE : 2,
            self.UAC_KEY_HOMEDIR_REQUIRED : 8,
            self.UAC_KEY_LOCKOUT : 16,
            self.UAC_KEY_PASSWD_NOTREQD : 32,
            self.UAC_KEY_PASSWD_CANT_CHANGE : 0,
            self.UAC_KEY_ENCRYPTED_TEXT_PWD_ALLOWED : 128,
            self.UAC_KEY_TEMP_DUPLICATE_ACCOUNT : 256,
            self.UAC_KEY_NORMAL_ACCOUNT : 512,
            self.UAC_KEY_INTERDOMAIN_TRUST_ACCOUNT : 2048,
            self.UAC_KEY_WORKSTATION_TRUST_ACCOUNT : 4096,
            self.UAC_KEY_SERVER_TRUST_ACCOUNT : 8192,
            self.UAC_KEY_DONT_EXPIRE_PASSWORD : 65536,
            self.UAC_KEY_MNS_LOGON_ACCOUNT : 131072,
            self.UAC_KEY_SMARTCARD_REQUIRED : 262144,
            self.UAC_KEY_TRUSTED_FOR_DELEGATION : 524288,
            self.UAC_KEY_NOT_DELEGATED : 1048576,
            self.UAC_KEY_USE_DES_KEY_ONLY : 2097152,
            self.UAC_KEY_DONT_REQUIRE_PREAUTH : 4194304,
            self.UAC_KEY_PASSWORD_EXPIRED : 8388608,
            self.UAC_KEY_TRUSTED_TO_AUTH_FOR_DELEGATION : 16777216,
            self.UAC_KEY_PARTIAL_SECRETS_ACCOUNT : 67108864,
        }
        
        ## A list of value keys for enabled flags.
        self.enabledFlags = []
        
    def disableFlag(self,uacFlag):
        '''
        Disables a UAC flag.
        
        Args:
            uacFlag: UAC flag key to remove from the list of enabled keys.
            
        Returns:
            True of the value was unset, False if it wasn't there to begin with.
        '''
        if uacFlag in self.enabledFlags:
            self.enabledFlags.remove(uacFlag)
            return True
            
        return False
        
    def enableFlag(self,uacFlag):
        '''
        Enables a UAC flag.
        
        Args:
            uacFlag: UAC flag key to add to the list of enabled keys.
            
        Returns:
            True if the value was properly set, False otherwise.
        '''
        
        if uacFlag not in self.enabledFlags:
            self.enabledFlags.append(uacFlag)
            return True
        else:
            return False
            
    def getFlagValue(self,uacFlag):
        '''
        Get the value of the specified flag.
        
        Args:
        uacFlag: The flag that we want to get the value for.
        
        Returns:
            The number that represents the requested UAC flag. If an invalid index is given, then 0 is returned.
        '''
        
        try:
            return self.uacFlagKeyValues[uacFlag]
        except KeyError:
            return 0
            
    def getSum(self,extraUacKeys=[],extraUacValues=[]):
        '''
        Compile UAC flags into a value.
        
        Args:
            extraUacKeys: A list of UAC keys to be added to the sum in addition to the enabled flags.
            extraUacValues: A list of integer values to add, in case there were some undocumented flags that I missed.
            
        Returns:
            An integer made of the sum of all activated UAC flags.
        '''
        
        flagSum = 0
        
        for i in self.enabledFlags:
            try:
                flagSum += int(self.uacFlagKeyValues[i])
            except KeyError:
                pass
        
        # Add extra flags.
        for uacKey in extraUacKeys:
            flagSum += self.getUacFlagValue(uacKey)
        
        # Add any extra values.
        for uacValue in extraValueList:
            flagSum += uacValue
            
        return flagSum
            
    def isFlagEnabled(self,uacFlag):
        '''
        Checks to see if a UAC flag has been enabled.
        
        Args:
            uacFlag: UAC flag that we are checking for.
        '''
            
    def sumUac(self,extraUacKeys,extraUacValues):
        '''
        Old name of getSum, kept around as an alias.
        
        Args:
            extraUacKeys: A list of UAC keys to be added to the sum in addition to the enabled flags.
            extraUacValues: A list of integer values to add, in case there were some undocumented flags that I missed.
            
        Returns:
            An integer made of the sum of all activated UAC flags.
        '''
        return self.getSum(extraUacKeys,extraUacValues)

class NullHandler(logging.Handler):
    """
    This handler does nothing. It's intended to be used to avoid the
    "No handlers could be found for logger XXX" one-off warning. This is
    important for library code, which may contain code to log events. If a user
    of the library does not configure logging, the one-off warning might be
    produced; to avoid this, the library developer simply needs to instantiate
    a NullHandler and add it to the top-level logger of the library module or
    package.

    This class was added manually to DirectoryTools because it didn't exist in Python until 2.7.
    """
    def handle(self, record):
        pass

    def emit(self, record):
        pass

    def createLock(self):
        self.lock = None
