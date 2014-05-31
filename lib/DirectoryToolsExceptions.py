
class ExceededMaxDepthException(Exception):
    '''
    Exception to be thrown when we dig too deeply into a group and exceed our value of MAX_DEPTH.
    '''
    
    def __init__(self,message='',depth=None,resultItem=[]):
        '''
        Initialize exception.
        
        Args:
            message: Debug message
            depth: The depth that we were at when we raised the exception.
            resultList: Contains any results that we still want to pass up. We may have searched too far, but we still need the information from the valid layers.
        '''
        ## Debug message
        self.message = message
        ## The depth that we were at when we raised the exception.
        self.depth = depth
        ## List of items that we searched for when we raised the exception
        self.resultItem = resultItem
        
    def __str__(self):
        '''
        toString of exception.
        '''
        return repr(self.parameters)

class PropertyNotFoundException(Exception):
    '''
    An exception to be raised when a property cannot be found.
    '''
    
    def __init__(self,key):
        '''
        Initializes the exception.
        
        Args:
            key: The property that could not be found.
        '''
        
        ## The property that could not be found.
        self.key = key
        
    def __str__(self):
        '''
        toString of exception.
        '''
        return repr(self.parameters)

class ExceptionWrapper(Exception):
    '''
    A wrapper for an exception. To be inherited by other Exceptions that use their name to help narrow down where they came from.
    '''
    
    def __init__(self,originalException):
        '''
        Initializes the exception.
        
        Args:
            originalException: The exception that triggered the except block that raised the exception.
        '''
        ## The exception that triggered the except block that raised the exception.
        self.originalException = originalException
        
    def __str__(self):
        '''
        toString of exception
        '''
        return repr(self.parameters)
        
class BadQueryException(ExceptionWrapper):
    '''
    To be triggered when something goes wrong with performing an LDAP query in DirectoryTools.query().
    '''
    def cause():
        ''' Gets a hard-coded explanation of the cause of this exception. '''
        return "There was an error with an LDAP query."
    
class ConnectionFailedException(ExceptionWrapper):
    '''
    To be triggered when something goes wrong with getting a handle.
    '''
    def cause():
        ''' Gets a hard-coded explanation of the cause of this exception. '''
        return "There was an error getting a connection handle."

class ProxyFailedException(ExceptionWrapper):
    '''
    To be triggered when something goes wrong with getting an authenticated proxy handle.
    '''
    def cause():
        ''' Gets a hard-coded explanation of the cause of this exception. '''
        return "There was an error getting a proxy handle."

class ProxyAuthFailedException(ExceptionWrapper):
    '''
    To be triggered when there was an authentication problem with the proxy handle.
    
    This may not always be reliable, as it expects the orginal LDAPErrorException to give a certain description to mark a problem as being due to authentication.
    '''
    def cause():
        ''' Gets a hard-coded explanation of the cause of this exception. '''
        return "Incorrect proxy credentials."

class ProxyFailedException(ExceptionWrapper):
    '''
    To be triggered when there was an unknown with getting an authenticated proxy handle.
    '''
    def cause():
        ''' Gets a hard-coded explanation of the cause of this exception. '''
        return "There was an error getting a proxy handle."
