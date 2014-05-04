#!/usr/bin/python

import DirectoryToolsIndexes as index
template = {}

def getTemplate(key):
    try:
        return template[key]
    except KeyError:
        return {}

template['openldap'] = {
    index.GROUP_CLASS:'posixGroup',
    index.USER_CLASS:'person',
    index.USER_INDEX_ATTRIBUTE:'cn',
    index.USER_UID_ATTRIBUTE:'uid',
    index.GROUP_INDEX_ATTRIBUTE:'cn',
    index.GROUP_UID_ATTRIBUTE:'uid',
    index.MEMBER_ATTRIBUTE:'memberUid',
    index.MEMBER_ATTRIBUTE_IS_DN:False,
    index.NESTED_GROUPS:False
}

template['ad'] = {
    index.GROUP_CLASS:'group',
    index.USER_CLASS:'person',
    index.USER_INDEX_ATTRIBUTE:'cn',
    index.USER_UID_ATTRIBUTE:'sAMAccountName',
    index.GROUP_INDEX_ATTRIBUTE:'cn',
    index.GROUP_UID_ATTRIBUTE:'sAMAccountName',
    index.MEMBER_ATTRIBUTE:'member',
    index.MEMBER_ATTRIBUTE_IS_DN:True,
    index.NESTED_GROUPS:True
}

template['freeipa'] = {
    index.GROUP_CLASS:'groupofnames',
    index.USER_CLASS:'person',
    index.USER_UID_ATTRIBUTE:'uid',
    index.GROUP_UID_ATTRIBUTE:'cn',
    index.MEMBER_ATTRIBUTE:'member',
    index.MEMBER_ATTRIBUTE_IS_DN:True,
    index.NESTED_GROUPS:True
}
