import urllib
import DirectoryTools
import DirectoryToolsIndexes as indexes

def getPostVariables(env,decodeValue=True):
    '''
    Gets the POST variables from a request that has been parsed through mod_wsgi.
    
    Args:
        env: Dictionary of environment variables.
        decodeString: A boolean flag. If True, content of the POST variable will be unsanitized.
    Returns:
        A dictionary of key/value pairs.
    '''
    
    # Each POST argument will be delimited by a '&'
    # A POST argument will be split into key/value pairs by a '='
    requestBodySize = int(env.get('CONTENT_LENGTH', 0))
    if requestBodySize is 0:
        # Don't bother searching for more, nothing to search through.
        return {}
        
    requestBody = env['wsgi.input'].read(requestBodySize)
            
    return processVariables(requestBody,decodeValue)
            
def processVariables(argString,decodeValue=True):
    '''
    Processes arguments sent to a WSGI application.
    This could be used by both POST and GET variables in the future, so I'm making it its own method.
    
    Args:
        argString: A string containing a group of key/value pairs.
        decodeString: A boolean flag. If True, the values in argString will be unsanitized.
    Returns:
        A dictionary of key/value pairs.
    '''
    
    variables = {}
    
    keyTerms = argString.split('&')
    for i in keyTerms:
        keyPair = i.split('=')
        try:
            if decodeValue:
                variables[keyPair[0]] = urllib.unquote(keyPair[1])
            else:
                variables[keyPair[0]] = keyPair[1]
        except KeyError:
            # The argument was submitted in a blank state. Putting in None instead.
            variables[keyPair[0]] = None
            
    return variables

def application(environ, start_response):
    post = getPostVariables(environ)
    #print post
    
    properties = {
        indexes.BASE_DN:'dc=openldap,dc=lan',
        indexes.SERVER_ADDRESS:'10.10.9.12',
        indexes.SERVER_PORT:'389',
        indexes.USE_SSL:False,
        indexes.PROXY_USER:'cn=admin,dc=openldap,dc=lan',
        indexes.PROXY_PASSWORD:'MyAdminPassword1!',
        indexes.DEBUG_LEVEL:3
    }
    
    trueResponse = "Success"
    falseResponse = "Failed"
    
    # Default response: False
    content = falseResponse
    
    try:
        dt = DirectoryTools.DirectoryTools(properties,'openldap')
        
        username = post.get('username',False);
        password = post.get('password',False);
        
        if username is not False and
            password is not False and
            dt.isUserInGroup(username,"VPN Access Group") and
            dt.authenticate(username,password):
            
            content = trueResponse
        
    except:
        # Something unexpected went wrong.
        pass
 
    response_headers = [('Content-type', 'text/html'),
                        ('Content-Length', str(len(content)))]
    start_response('200 OK', response_headers)
 
    return [content]
