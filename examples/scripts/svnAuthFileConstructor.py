#!/usr/bin/python

import string, argparse, os.path, DirectoryTools

properties = {}

def loadArguments():
    '''
    Load a configuration file.
    '''
    parser = argparse.ArgumentParser(description='Construct an SVN authorization file.')
    parser.add_argument("-c", help="DirectoryTools configuration file.",required=True)
    args = parser.parse_args()

    errors = []
    
    if not os.path.isfile(args.c):
        errors.append("ERROR: Configuration file does not exist")
    else:
        global configFile
        configFile = args.c
        
    if(len(errors) > 0):
        print "Errors found."
        for i in errors:
            print i
        exit(1)
    
def run(groups,dtConfigFileFile,dtTemplate):
    
    global dt
    dt = DirectoryTools.DirectoryTools(template=dtTemplate,configFile=dtConfigFileFile,enableStdOut=False)
    
    paths = {}
    for permission in groups:
        for groupName in groups[permission]:
            for permissionPath in groups[permission][groupName]:
                if permissionPath not in paths:
                    paths[permissionPath] = {}
                if permission not in paths[permissionPath]:
                    paths[permissionPath][permission] = []
                paths[permissionPath][permission].append(groupName)
                
    # Construct groups section.
    groupMemberList = {}
    for permission in groups:
        for groupName in groups[permission]:
            if groupName not in groupMemberList:
                groupMemberList[groupName] = []
            groupMemberList[groupName] += dt.getUsersInGroup(groupName)
            # Dedupe the member list for tidiness.
            groupMemberList[groupName] = list(set(groupMemberList[groupName]))

    groupMemberSection = "[groups]\n"
    for groupName in groupMemberList:
        groupMemberSection += "{0} = {1}\n".format(groupName,string.join(groupMemberList[groupName],','))
    returnContent = groupMemberSection

    # Construct permissions for paths.
    permissionSection = ""
    for permissionPath in paths:
        permissionSection += "\n[{0}]\n".format(permissionPath)
        for permission in paths[permissionPath]:
            permissionSection += "{0} = @{1}\n".format(permission,string.join(paths[permissionPath][permission],','))
    return groupMemberSection + permissionSection

if __name__ == '__main__':
    loadArguments()
    
    groups = {'r':{},'rw':{}}
    groups['rw']['employees'] = ['/']

    fileContents = run(groups,configFile,'ad')
    print fileContents
