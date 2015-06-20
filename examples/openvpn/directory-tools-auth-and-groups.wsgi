from cgi import parse_qs, escape

# No idea why, but sometimes sys.path doesn't include my module properly.
# It must be something about ModWSGI that I don't entirely understand.
# This seemed to go away after a while, but leaving this here just in case.
import sys
dtPath='/usr/local/lib/python2.7/dist-packages/DirectoryTools-0.1-py2.7.egg'
if dtPath not in sys.path:
    sys.path.insert(0,dtPath)
import DirectoryTools

REQUEST_TYPE_PASSWORD = "auth"
REQUEST_TYPE_GROUPS = "groups"

# All clear.
RESULT_SUCCESS = 0
# Unexpected exception was thrown.
RESULT_UNEXPECTED_ERROR = 1
# Unknown request type.
RESULT_UNKNOWN_REQUEST = 2
# User was unable to authenticate.
RESULT_BAD_CREDENTIALS = 3
# Unknown user.
RESULT_UNKNOWN_USER = 4
# Empty output. Result of programmer error
RESULT_EMPTY_OUTPUT = 5
# Bad "authentication token"
RESULT_BAD_TOKEN = 6

# A crude authentication token to make sure that only an authorized client is reaching the app.
authToken = "crude-security-password"

# Other than VPN access groups, any site-specific information is in the DirectoryTools configuration file.
dt = DirectoryTools.DirectoryTools(False,'openldap','/path/to/web/server/wsgi/scripts/dt-config.ini')

def getValue(d,key,default=False):
    '''
    The dictionary of GET or POST vars contians a list as the value for each key,
        in case the client has multiple entries under the same key.
    My use case assumes that each key is only given once, so if we get a list we will
        only return the first index.
    '''

    value = d.get(key,default)
    if type(value) is list and len(value) > 0:
        value = value[0]
    return value

def getPostVars(environ):
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except (ValueError):
        request_body_size = 0

    request_body = environ['wsgi.input'].read(request_body_size)
    return parse_qs(request_body)

def run(environ):
    outputFormat='{0}:{1}'

    output = False        
    getVars = parse_qs(environ["QUERY_STRING"])
    postVars = getPostVars(environ)

    # We have set a password on the web app.
    # Check to see if the client has provided it.
    if authToken and authToken != getValue(postVars,"token","no"):
        return outputFormat.format(RESULT_BAD_TOKEN,"")

    requestType = getValue(getVars,"type","default");

    try:
        if requestType == REQUEST_TYPE_PASSWORD:
            # ToDo: Replace with DT call.
            user = getValue(postVars,"user")
            password = getValue(postVars,"password")
            
            # Accept the user if they successfully authenticate and are a member of an access group.
            if user and password and dt.authenticate(user,password) and ( user in dt.getGroupMembers("vpn-access") or user in dt.getGroupMembers("admin-group") ):
                # If you also want to filter by groups,
                #    add the following condition to the above IF statement
                # and user in dt.getGroupMembers("vpn-access-group")
                output = outputFormat.format(RESULT_SUCCESS,"")
            else:
                output = outputFormat.format(RESULT_BAD_CREDENTIALS,"")
        elif requestType == REQUEST_TYPE_GROUPS:
            user = getValue(postVars,"user")
            if user:
                output = outputFormat.format(RESULT_SUCCESS," ".join(dt.getUserGroups(user)))
            else:
                output = outputFormat.format(RESULT_UNKNOWN_USER,"")
        else:
            output = outputFormat.format(RESULT_UNKNOWN_REQUEST,"")
    except:
        # Unexpected error
        output = outputFormat.format(RESULT_UNEXPECTED_ERROR,"")
        import traceback
        traceback.print_exc(file=sys.stdout)

    if not output:
        output = outputFormat.format(RESULT_EMPTY_OUTPUT,"")

    return output

def application(environ, start_response):
    status = '200 OK'

    output = run(environ)

    response_headers = [('Content-type', 'text/plain'),
                        ('Content-Length', str(len(output)))]
    start_response(status, response_headers)
 
    return [output]
