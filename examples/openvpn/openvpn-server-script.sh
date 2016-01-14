#!/bin/sh

######################################################################################
# OpenVPN Server Script for authentication and access rules based on LDAP groups.    #
#    Made for lightweight servers (like those running on OpenWRT, for instance) that #
#      can't necessarily support Python and Directory tools on their own by          #
#      middle-manning through a Python script run through ModWSGI.                   #
#                                                                                    #
#        Set configuration variables below under the function definitions!           #
######################################################################################

urlencode(){
    local length="${#1}";
    for ((i = 0; i < length; i++ ))
    do
        local c="${1:i:1}";
        case $c in
            [a-zA-Z0-9.~_-])
                printf "$c"
            ;;
            *)
                printf '%s' '$c' | xxd -p -c1 | while read c; do
                    printf '%%%s' "$c";
                done
            ;;
        esac;
    done;
    unset i
}

apply_iptables_rule(){
    local subject=$1
    local filter=$2

    # echo "Applying rule to $subject. Filter: $filter"

    if [ -n "$subject" ] && [ -n "$filter" ]; then
        $IPTABLES -I "$OPENVPN_CHAIN" -s $subject $filter -j ACCEPT -m comment --comment "$RULE_COMMENT (user:$username,ip:$subject,type:regular_rule)"
    fi
}

apply_special_iptables_rule(){
    local subject=$1
    local filter=$2

    # echo "Applying rule to $subject. Filter: $filter"

    #echo $IPTABLES -I "$OPENVPN_CHAIN" -s $subject $filter -j ACCEPT -m comment --comment "$RULE_COMMENT"
    if [ -n "$subject" ] && [ -n "$filter" ]; then
        $IPTABLES -I "$OPENVPN_SPECIAL_RULES_CHAIN" $filter -j ACCEPT -m comment --comment "$RULE_COMMENT (user:$username,ip:$subject,type:special_rule)"
    fi
}

apply_self_iptables_rules(){
    # IP of new client
    local new_ip=$1
    # IP of existing client
    local existing_ip=$2

    # echo "Applying self-access rules to machines belonging to $username"
    
    if [ -n "$existing_ip" ]; then
        existing_comment=$(format_comment "$existing_ip")
        $IPTABLES -I "$OPENVPN_SELF_RULES_CHAIN" -s $new_ip -d $existing_ip -j ACCEPT -m comment --comment "$RULE_COMMENT $existing_comment (user:$username,ip:$new_ip->$existing_ip,type:self_access_rule)"
        $IPTABLES -I "$OPENVPN_SELF_RULES_CHAIN" -s $existing_ip -d $new_ip -j ACCEPT -m comment --comment "$RULE_COMMENT $existing_comment (user:$username,ip:$existing_ip->$new_ip,type:reverse_self_access_rule)"
    fi
}

apply_rules(){
    flush_rules_for_host
    groups=$(remote_call "groups" "user=$(urlencode "$username")" | cut -d':' -f 2)
    #echo "Groups: $groups"
    if [ -n "$groups" ]; then
        for group in $groups; do
            #echo "Attempting to apply rule for $group group"
            case "$group" in
            "admin-group")
                # If a user is a member of the admin group, then they are trusted enough to access any local network resource.
                # Also let admins go and use the 'redirect-gateway' option to redirect their traffic.
                # If anyone else tried to use 'redirect-gateway', they would be blocked by pre-existing firewall rules.
                apply_iptables_rule "${SUBJECT}" "-d 0.0.0.0/0"
                ;;
            "vpn-access")
                # Apply common rules to anyone in the base VPN access group.
                apply_iptables_rule "$SUBJECT" "-d $address_web_server -p tcp -m multiport --dports 80,443"
                apply_iptables_rule "$SUBJECT" "-d $address_web_server -p icmp"
                apply_iptables_rule "$SUBJECT" "-d $address_dns -p udp -m multiport --dports 53"
                ;;
            "web-server-shell-access")
                # Allow SSH access to web server.
                apply_iptables_rule "$SUBJECT" "-d $address_web_server -p tcp --dport 22"
                ;;
            esac
        done
    fi
    
    # Apply special rules based on username.
    case "$username" in
    "special-user")
        apply_special_iptables_rule ${SUBJECT} "-s 192.168.1.0/24 -d 192.168.0.0/24"
        ;;
    esac
    
    # Check to see if there are any other cases of the connecting username.
    if [ -n "$STATUS_FILE" ] && [ -f "$STATUS_FILE" ]; then
        for instance in $(cat "$STATUS_FILE" | grep ",$username," | sed "/:${trusted_port},/d" | cut -d, -f 1); do
            apply_self_iptables_rules "${SUBJECT}" "${instance}"
        done
    fi

}

create_structure(){

    if ! iptables -nvL "$OPENVPN_CHAIN" 2> /dev/null >&2; then
    
        echo "Creating $OPENVPN_CHAIN..."
    
        $IPTABLES -N "$OPENVPN_CHAIN" 2> /dev/null
        
        # We will now be working with an empty chain, one way or the other. Add default rules.
        $IPTABLES -A "$OPENVPN_CHAIN" -j DROP -m comment --comment "$OPENVPN_INSTANCE Fallback DROP Rule"
    fi
    
    # Make a table for special per-client rules
    if ! iptables -nvL "$OPENVPN_SPECIAL_RULES_CHAIN" 2> /dev/null >&2; then
        echo "Creating $OPENVPN_SPECIAL_RULES_CHAIN..."
        $IPTABLES -N "$OPENVPN_SPECIAL_RULES_CHAIN"
    fi
    
    # Make a table for allowing clients to get at their other devices
    if ! iptables -nvL "$OPENVPN_SELF_RULES_CHAIN" 2> /dev/null >&2; then
        echo "Creating $OPENVPN_SELF_RULES_CHAIN..."
        $IPTABLES -N "$OPENVPN_SELF_RULES_CHAIN"
    fi
    
    if echo "${script_type}" | grep -q '^up$'; then
        # If we are bringing up the OpenVPN server, flush for good measure in case any old rules stayed around.
        
        # Main chain
        $IPTABLES -F "$OPENVPN_CHAIN"
        # Re-add default rule for main chain.
        $IPTABLES -A "$OPENVPN_CHAIN" -j DROP -m comment --comment "$OPENVPN_INSTANCE Fallback DROP Rule"
        # Special rules
        $IPTABLES -F "$OPENVPN_SPECIAL_RULES_CHAIN"
        # Self rules
        $IPTABLES -F "$OPENVPN_SELF_RULES_CHAIN"
    fi
    
    local parent_chain=$1

    if [ -n "$parent_chain" ]; then
        echo "Confirming target chain: $OPENVPN_CHAIN"
        # Check that the parent chain exists and does
        #     not currently have a link to the VPN rules.
        echo "Checking to attach to parent chain: $parent_chain"
        
        if iptables -nvL  "$parent_chain" 2> /dev/null >&2; then
        
            if ! iptables -nvL "$parent_chain" 2> /dev/null | grep -q "$OPENVPN_CHAIN"; then 
                $IPTABLES -I $parent_chain -i "$OPENVPN_INTERFACE" -j $OPENVPN_CHAIN 2> /dev/null
            fi

            if ! iptables -nvL "$parent_chain" 2> /dev/null | grep -q "$OPENVPN_SPECIAL_RULES_CHAIN"; then 
                $IPTABLES -I $parent_chain -j $OPENVPN_SPECIAL_RULES_CHAIN 2> /dev/null
            fi

            if ! iptables -nvL "$parent_chain" 2> /dev/null | grep -q "$OPENVPN_SELF_RULES_CHAIN"; then 
                $IPTABLES -I $parent_chain -i "$OPENVPN_INTERFACE" -o "$OPENVPN_INTERFACE" -j $OPENVPN_SELF_RULES_CHAIN 2> /dev/null
            fi
        fi
    fi
}

flush_rules_for_host(){
    if [ -n "$RULE_COMMENT" ]; then
        for chain in $OPENVPN_CHAIN $OPENVPN_SPECIAL_RULES_CHAIN $OPENVPN_SELF_RULES_CHAIN; do
            patterns="$RULE_COMMENT"
            # Below: Add an extra pattern to confirm by username that things are missing.
            # WARNING: THIS WILL CONFLICT WITH ALLOWING MULTIPLE HOSTS PER CLIENT
            #if [ -n "$username" ]; then
            #    patterns="$patterns $(echo "user:$username," | sed 's/\ /_/g')"
            #fi
            for pattern in $patterns; do
                echo "Flush rules matching $pattern in $chain"
                for line in $(iptables -nvL "$chain" --line-numbers | grep "$pattern" |  grep '^[0-9]' | cut -d' ' -f 1 | sort -rn); do
                    if [ ! -z "$line" ]; then
                        # Axe the previous rule if it exists.
                        $IPTABLES -D $chain $line
                    fi
                done
            done
        done
    fi
}

do_client_connect(){
    set_variables
    create_structure "forwarding_rule"
    apply_rules
}

do_client_disconnect(){
    set_variables
    create_structure "forwarding_rule"
    flush_rules_for_host
}

do_authenticate(){
    set_variables
    
    local response=$(remote_call "auth" "user=$(urlencode "$username")&password=$(urlencode "$password")")

    echo "Response: $response"

    if [ -z "$response" ]; then
        exit 1
    fi

    local response_code=$(echo $response | cut -d':' -f 1)
    exit $response_code
}

do_up(){
    set_variables
    
    ping $CURL_IP -c 1 > /dev/null 2> /dev/null || return 0
    
    # Parse configuration for pool file
    if [ -f "$config_file" ]; then
        # If $dev is not set, parse config for device file variable (for if this is run from /etc/firewall.user).
        # Luckily, there seem to be no other switches to OpenVPN ending in "dev"
        if [ -z "$dev" ]; then
            raw_dev=$(cat "$config_file" | grep dev\  | awk '{print $2}')
            # ToDo later: Account for TAP interfaces.
            OPENVPN_INTERFACE=$(echo $raw_dev | egrep tun[0-9]{1,})
            if [ -z "$OPENVPN_INTERFACE" ]; then
                OPENVPN_INTERFACE="$raw_dev+"
            fi
        fi
        
        create_structure "forwarding_rule"
        
        # For the purposes of this setup, device is assumed to be statically set.
        # Parse config for pool variable (currently not in use, since I do not trust the pool file's contents anymore).
        #local pool_file=$(cat "$config_file" | grep ifconfig-pool-persist | awk '{print $2}')
        
        if [ -n "$pool_file" ] && [ -f "$pool_file" ]; then
            while read line; do
                if [ -n "$line" ]; then
                    # Simluate the required variables that would be set for a client-connect instance to 
                    #     simulate the environment.
                    username=$(echo "$line" | cut -d',' -f 1)
                    ifconfig_pool_remote_ip=$(echo "$line" | cut -d',' -f 2)
                    # Reset variables for new subject.
                    set_variables
                    apply_rules
                fi
            done < "$pool_file"
        
        
        fi  
    fi
    
    return 0 
}

format_comment(){
    echo "$RULE_HEADERS$(echo ${1} | sed 's/\./_/g')_"
}

remote_call(){
    local type=$1
    local postData=$2
    local getData=$3

    if [ -n "getData" ]; then
        local curlPath="$CURL_URL?type=$type&$getData"
    else
        local curlPath="$CURL_URL?type=$type"
    fi

    if [ -n "$TOKEN" ] && [ -n "$postData" ]; then
        postData="token=$(urlencode "$TOKEN")&$postData"
    elif [ -n "$TOKEN" ]; then
        postData="$(urlencode "$TOKEN")"
    fi

    if [ -n "$postData" ]; then
        curl -s $OTHER_CURL_SWITCHES -X POST --data "$postData" $curlPath
    else
        curl -s $OTHER_CURL_SWITCHES $curlPath
    fi
}

set_instance_name(){
    # Override default instance name.
    if [ -n "$1" ]; then
        OPENVPN_INSTANCE="$1"
        OPENVPN_CHAIN="$OPENVPN_INSTANCE-rules"
        OPENVPN_SPECIAL_RULES_CHAIN="$OPENVPN_INSTANCE-special-rules"
        OPENVPN_SELF_RULES_CHAIN="$OPENVPN_INSTANCE-self-rules"
    fi
}

set_variables(){
    # Set dynamic variables.
    config_file=${CONFIG_DIR}/${config:-openvpn.conf}
    set_instance_name "$(basename "$config_file" | cut -d'.' -f 1)"
    SUBJECT=$ifconfig_pool_remote_ip
    RULE_COMMENT=$(format_comment "${SUBJECT}")
    if [ -f "$config_file" ]; then
        STATUS_FILE=$(cat "$config_file" | grep ^status\  | awk '{print $2}')
    fi
}

# Define static shortcuts for server resources
address_web_server=192.168.0.2
address_dns_server=192.168.0.1

# Define commands and static variables for iptables rules.
# Using echo as a debug for development
IPTABLES="iptables"
CONFIG_DIR=/etc/openvpn
OPENVPN_INTERFACE=$dev
# Default instance name.
set_instance_name "openvpn"
RULE_HEADER="host_"

CURL_IP="$address_web_server"
CURL_URL="https://$CURL_IP/auth"
TOKEN="crude-security-password"
OTHER_CURL_SWITCHES="-k"

case "${script_type:-sourced}" in
"client-connect")
    do_client_connect
    ;;
"client-disconnect")
    do_client_disconnect
    ;;
"user-pass-verify")
    do_authenticate
    ;;
"up")
    do_up
    ;;
esac
