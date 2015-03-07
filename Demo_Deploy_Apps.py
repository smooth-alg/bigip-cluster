#!/usr/bin/env python
'''
----------------------------------------------------------------------------
The contents of this file are subject to the "END USER LICENSE AGREEMENT FOR F5
Software Development Kit for iControl"; you may not use this file except in
compliance with the License. The License is included in the iControl
Software Development Kit.

Software distributed under the License is distributed on an "AS IS"
basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
the License for the specific language governing rights and limitations
under the License.

The Original Code is iControl Code and related documentation
distributed by F5.

The Initial Developer of the Original Code is F5 Networks,
Inc. Seattle, WA, USA. Portions created by F5 are Copyright (C) 1996-2004 F5 Networks,
Inc. All Rights Reserved.  iControl (TM) is a registered trademark of F5 Networks, Inc.

Alternatively, the contents of this file may be used under the terms
of the GNU General Public License (the "GPL"), in which case the
provisions of GPL are applicable instead of those above.  If you wish
to allow use of your version of this file only under the terms of the
GPL and not to allow others to use your version of this file under the
License, indicate your decision by deleting the provisions above and
replace them with the notice and other provisions required by the GPL.
If you do not delete the provisions above, a recipient may use your
version of this file under either the License or the GPL.
----------------------------------------------------------------------------
'''



def get_LTConfig_field_values ( obj, my_class, container, container_class, fields ):
    #fields param = dict of field names
    try:
	class_instance_key = { 'name' : my_class , 
			       'class_name' : my_class }
# 			       'container' : container, 
#			       'container_class' : "None" 
#			    } 

	field_instance_names = []
	for k,v in fields.items():
	    #print "%-30s" % k 
	    field_instance_names.append(k)

        values_output = obj.LTConfig.Field.get_values( 
                    class_instance_keys = [ class_instance_key ] , 
                    field_instance_names = [ field_instance_names ], 
                    )

    
        print "%-30s" % "field" + "%s" % "value"
        print "%-30s" % "-----" + "%s" % "-----"

        for i in range(len(field_instance_names)):
            print (
		   "%-30s" % field_instance_names[i].strip() + 
		      "%s" % values_output[0][i].replace('\n','\n\t\t\t\t').strip()
		  )

        return values_output

    except:
        print "Get " + my_class + " config error. Check log."
        traceback.print_exc(file=sys.stdout)



def set_LTConfig_field_values ( obj, my_class, container, container_class, fields_values ):

#   Possible Values for Class on v11.5.1
#     >>> b.LTConfig.Class.get_list()
#     ['auth_source', 'apmclient', 'cli', 'confpp', 'daemon_clusterd', 'daemon_csyncd', 'daemon_lind', 'daemon_mcpd', 'daemon_tmm', 'dns', 'httpd', 'internal', 'logrotate', 'ltm', 'ntp', 'restrict', 'password_policy', 'persist', 'remote_users', 'remoterole', 'role_info', 'snmpd', 'community', 'disk', 'proc', 'trapsess', 'trapsink', 'trap2sink', 'usmuser', 'sshd', 'statemirror', 'syslog', 'remote_server', 'system', 'remote_host', 'profile_scim', 'profile_eam', 'profile_mblb', 'profile_ntlm', 'profile_pluginclass', 'profile_rba', 'profile_sso', 'profile_smtp', 'outboundsmtp']
# 

    try:
        class_instance_key = { 
				'name' : my_class , 
			        'class_name' : my_class }
				#'container' : container,
				#'container_class' : container_class }
	field_instance_names = []
        values = []
	print "%-30s" % "keys" + "%s" % "values"
        print "%-30s" % "----" + "%s" % "------"
	for k,v in fields_values.items():
	    print "%-30s" % k + "%s" % v
	    field_instance_names.append(k)
	    values.append(v)

        obj.LTConfig.Field.set_values( 
                    create_instances_if_needed = 1, 
                    class_instance_keys = [ class_instance_key ] , 
                    field_instance_names = [ field_instance_names ] , 
                    values = [ values ]  )

    except:
        print "Set " + my_class + " config error. Check log."
        traceback.print_exc(file=sys.stdout)





def certificate_export_to_PEM( obj, cert_mode, cert_id ):

    try:
	mode = cert_mode
        cert_ids = [[ cert_id ]]

        certs_output = obj.Management.KeyCertificate.certificate_export_to_pem( 
                                                                                mode,  
                                                                                cert_ids
                                                                              )
        return certs_output

    except:
        print "Certificate Export to PEM Error. Check log."
        traceback.print_exc(file=sys.stdout)               
                                                 

def certificate_import_from_PEM( obj, cert_mode, cert_id, my_cert_pem ):

    try:

        # This can be used to upload certs to BIGIP, example if using your own CA
        # Just change cert_mode to appropriate type:

        mode = cert_mode
        cert_ids = [ cert_id ]
        pem_data = [ my_cert_pem ]
        overwrite = bool(1)

        certs_output = obj.Management.KeyCertificate.certificate_import_from_pem( 
                                                                                mode, 
                                                                                cert_ids,
                                                                                pem_data,
                                                                                overwrite
                                                                              )
        return certs_output

    except:
        print "Certificate Import from PEM Error. Check log."
        traceback.print_exc(file=sys.stdout)               


def set_hostname (obj, hostname ):

    try:

        obj.System.Inet.set_hostname( hostname = hostname )
        

    except:
        print "Set hostname change error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_hostname (obj ):

    try:

        hostname = obj.System.Inet.get_hostname()
        print "Hostname is set to: \"" + hostname + "\""

    except:
        print "Get hostname error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_ltm_global_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'ltm', 'None', 'None', fields )

    except:
        print "Set LTM Global Config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_ltm_global_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'ltm', 'None', 'None', fields )

    except:
        print "get LTM Global Config error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_vlans (obj, vlans, vlan_ids, members, tagged, failsafe_states, timeouts , mac_masquerade_addresses  ):

    # interface creates one or many vlans 
    # feed it arrays 
    # but for simplicity only takes one one interface per vlan (which is in most case a tagged trunk)

    try:
        vlans_seq = vlans
        vlan_ids_seq = vlan_ids
	members_seq_seq = []

        for i in range(len(vlans)):

	    member_seq = []

	    member_name =  members[i]
	    member_type = ""
	    tag_state = ""

            if re.match( r'^\d+\.\d+$', members[i] ):
                member_type = "MEMBER_INTERFACE"
            else:
                member_type = "MEMBER_TRUNK"

            if bool(tagged[i]):
                tag_state = "MEMBER_TAGGED"
            else:
		tag_state = "MEMBER_UNTAGGED"

	    member_entry = { 'member_name': member_name , 'member_type': member_type , 'tag_state' : tag_state}
            members_seq = [member_entry]
            members_seq_seq.append(members_seq)

        failsafe_states_seq = failsafe_states
        timeouts_seq = timeouts
	mac_masquerade_addresses_seq = mac_masquerade_addresses
	# Commenting out: Set on traffic groups now!
        # Check to see if any mac masq addresses are passed. 
        # Otherwise, set them manually based on mgmt mac
#         mac_masquerade_addresses_is_empty = bool(True)
#         
#         for mac in mac_masquerade_addresses:
#             if mac:
#                 mac_masquerade_addresses_is_empty = bool(False)
# 
#         mac_masquerade_addresses_seq = []
#         if mac_masquerade_addresses_is_empty:
#             mgmt_mac_seq = b.Networking.Interfaces.get_mac_address(["mgmt"])
#             mac_masq = re.sub( r':(\d\w+)$', ":F5", mgmt_mac_seq[0] , )
#             for i in range(len(vlans)):
#                 mac_masquerade_addresses_seq.append("00:00:00:00:00:00")
#                 #mac_masquerade_addresses_seq.append(mac_masq)
# 

        obj.Networking.VLAN.create(
                                vlans = vlans_seq, 
                                vlan_ids = vlan_ids_seq, 
                                members = members_seq_seq, 
                                failsafe_states = failsafe_states_seq, 
                                timeouts = timeouts_seq, 
                                mac_masquerade_addresses = mac_masquerade_addresses_seq
                            )

    except:
        print "Set VLAN config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_vlans (obj  ):

    try:
        
        vlan_name_seq = obj.Networking.VLAN.get_list()
        vlan_id_seq = obj.Networking.VLAN.get_vlan_id( vlan_name_seq )
        member_seq = obj.Networking.VLAN.get_member( vlan_name_seq )
        failsafe_state_seq = obj.Networking.VLAN.get_failsafe_state( vlan_name_seq )
        failsafe_timeout_seq = obj.Networking.VLAN.get_failsafe_timeout( vlan_name_seq )
        mac_masquerade_address_seq = obj.Networking.VLAN.get_mac_masquerade_address( vlan_name_seq )
        
        for v in range(len(vlan_name_seq)):
            print ""
            print "%-25s" % "Vlan Name:"            + "%-25s" % vlan_name_seq[v] 
            print "%-25s" % "----------------"      + "%-25s" % "----------------"
            print "%-25s" % "Vlan ID:"              + "%-25s" % vlan_id_seq[v]
            
            print "%-25s" % "Failsafe State:"       + "%-25s" % failsafe_state_seq[v]
            print "%-25s" % "Failsafe Timeout:"     + "%-25s" % failsafe_timeout_seq[v]
            print "%-25s" % "Mac Masq Addr:"        + "%-25s" % mac_masquerade_address_seq[v]
            for i in range(len(member_seq[v])):
		member = member_seq[v][i]		
		print "%-25s" % "Member Name  =>"     + "%-25s" % member['member_name']
                print "%-28s" % "Member Type  =>"     + "%-25s" % member['member_type']
                print "%-28s" % "Tagged State =>"     + "%-25s" % member['tag_state']

    except:
        print "Get VLAN config error. Check log."
        traceback.print_exc(file=sys.stdout)
 

def set_self_ips( obj, names, addresses, netmasks, vlan_names, traffic_groups, floating_states, port_lock_down_list, custom_ports ):
    try:

        obj.Networking.SelfIPV2.create(
                                        self_ips = names,
					addresses = addresses,
                                        netmasks = netmasks,
                                        vlan_names = vlan_names,
                                        traffic_groups = traffic_groups,
                                        floating_states = floating_states
                                    )
        #Example Output for
        # Allow Default
        # [{'mode': 'ALLOW_MODE_DEFAULTS', 'protocol_ports': []}]
        # 'protocol_ports': [{'protocol': 'PROTOCOL_ANY', 'port': 0}, {'protocol': 'PROTOCOL_UNKNOWN', 'port': 0}]}]
        # Allow All
        # [{'mode': 'ALLOW_MODE_ALL', 'protocol_ports': []}]
        # Default  + BGP  ### NOT WORKING? ###
        # [{'mode': 'ALLOW_MODE_PROTOCOL_PORT',
        #   'protocol_ports': [{'protocol': 'PROTOCOL_TCP', 'port': 179}, {'protocol': 'PROTOCOL_UNKNOWN', 'port': 0}]}]
        # Just BGP
        #[{'mode': 'ALLOW_MODE_PROTOCOL_PORT', 'protocol_ports': [{'protocol': 'PROTOCOL_TCP', 'port': 179}]}]
        # Allow None
        # [{'mode': 'ALLOW_MODE_NONE', 'protocol_ports': []}]
        access_list_seq = []
        for i in range(len(names)):
            #print "Custom Ports are : " + str(custom_ports[i])
            port_pairs = custom_ports[i].split(",")
            proto_port_objs = []
            for pair in port_pairs:
                #Some Wild Assumptions here
                proto,port = pair.split(":")
                proto_port_obj = { 'protocol': "PROTOCOL_" + proto.upper(), 'port' : port }
                proto_port_objs.append(proto_port_obj)

            print "Self IP is : " + names[i]
            print "Proto_port_objs are: "
            access_obj = {
                            'mode'      : port_lock_down_list[i],
                            'protocol_ports' : proto_port_objs
                         }
            access_list_seq.append(access_obj)



        obj.Networking.SelfIPV2.add_allow_access_list( self_ips = names, access_lists = access_list_seq )
               

    except:
        print "Set SelfIP config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_self_ips( obj):
    try:

        self_ip_seq = obj.Networking.SelfIPV2.get_list()
        addresses_seq = obj.Networking.SelfIPV2.get_address( self_ip_seq )
        netmasks_seq = obj.Networking.SelfIPV2.get_netmask( self_ip_seq )
        vlan_names_seq = obj.Networking.SelfIPV2.get_vlan( self_ip_seq )
        traffic_group_seq = obj.Networking.SelfIPV2.get_traffic_group( self_ip_seq )
        floating_states_seq = obj.Networking.SelfIPV2.get_floating_state( self_ip_seq )
        access_list_seq = obj.Networking.SelfIPV2.get_allow_access_list ( self_ip_seq )

        for v in range(len(self_ip_seq)):
            print ""
            print "%-25s" % "SelfIP:"               + "%-25s" % self_ip_seq[v] 
            print "%-25s" % "----------------"      + "%-25s" % "----------------"
            print "%-25s" % "Address:"              + "%-25s" % addresses_seq[v]
            print "%-25s" % "Netmask:"              + "%-25s" % netmasks_seq[v]
            print "%-25s" % "Vlan:"                 + "%-25s" % vlan_names_seq[v]
            print "%-25s" % "Traffic Group:"        + "%-25s" % traffic_group_seq[v]
            print "%-25s" % "Floating State:"       + "%-25s" % floating_states_seq[v]  
	    print "%-25s" % "Port Lock Down Mode=>" + "%-25s" % access_list_seq[v]['mode']


    except:
        print "Get SelfIP config error. Check log."
        traceback.print_exc(file=sys.stdout)

def return_network_dot_quad ( ip, netmask ):

    # Takes dot quad ip and netmask string and returns network string
    # Note: Does not take IPV6. Would need Socket v2.3 w/ socket.inet_pton & inet_ntop 
    try:
            ip_int = ip2int(ip)
            netmask_int = ip2int(netmask)
            ip_net_int = ip_int & netmask
            ip_net = int2ip(ip_net_int)
            return ip_net 

    except:
        print "Could not return network"


def set_gateway_pools (obj, self_ips, self_ips_netmasks, vlans ):

    # Convenience function to autopopulate the vlans with gateway pools
    # Takes arrays of dot quad ip and netmask strings
    # Note: Does not take IPV6. Would need Socket v2.3 w/ socket.inet_pton & inet_ntop 

    try:

        gateway_networks = []
	gateway_network_masks = []
        gateways = []
        vlan_names = []
        
        for i in range(len(self_ips)):
            self_ip_int = ip2int(self_ips[i])
            netmask_int = ip2int(self_ips_netmasks[i])
            self_ip_network_int = self_ip_int & netmask_int
	    self_ip_network = int2ip(self_ip_network_int)

            if self_ip_network not in gateway_networks:     
                gateway_networks.append(self_ip_network)
		gateway_network_masks.append(self_ips_netmasks[i])
                vlan_names.append(vlans[i])
            
        for i in range(len(gateway_networks)):
            # Assumes gateway is first ip in the network
            gateway_address_int = ip2int(gateway_networks[i]) + 1
	    # Asssumes gateway if last ip in the network
	    host_mask = ip2int("255.255.255.255") ^ ip2int(gateway_network_masks[i])
	    broadcast_int = ip2int(gateway_networks[i]) | host_mask
	    gateway_address_int = broadcast_int - 1

            gateway_address = int2ip(gateway_address_int)
            gateways.append(gateway_address)

        pool_port = 0
        lb_method = "LB_METHOD_ROUND_ROBIN"
        monitor = "gateway_icmp"
        for i in range(len(gateways)):
            pool_name = vlan_names[i] + "_gateway_pool"
	    member = gateways[i]
	    print "gateway_address is " + member
            create_pool( obj, [ pool_name ], [[ member ]], [[ pool_port ]] , [ lb_method ], [ monitor ] )
	    

    except:
        print "Set Gateway Pool error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_gateway_pools( obj ):

    try:
        pool_seq = obj.LocalLB.Pool.get_list()
        gateway_pool_seq = []
        for pool in pool_seq:
            if "gateway" in pool:
                gateway_pool_seq.append(pool)

        get_pool( obj, gateway_pool_seq )

    except:
        print "Get Gateway Pool error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_static_routes( obj, route_names , route_nets, route_masks, route_gws ):
    try:
	
	destinations = [ ]
	attributes = [ ]

        for i in range(len(route_nets)):
                route_dest_obj = {     'address' : route_nets[i], 
				       'netmask' : route_masks[i] }
                destinations.append(route_dest_obj)

                route_attribute_obj = { 'gateway' : route_gws[i] }
                attributes.append(route_attribute_obj)
   
        obj.Networking.RouteTableV2.create_static_route(
							routes = route_names, 
                                                        destinations = destinations, 
                                                        attributes = attributes
                                                       )

    except:
        print "Set Route config error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_static_routes ( obj ):

    try:
        
	static_route_names = []
	static_route_nets = []
        static_route_masks = []
        static_route_gws = []

        static_route_names_output = obj.Networking.RouteTableV2.get_static_route_list() 
        static_route_destinations = obj.Networking.RouteTableV2.get_static_route_destination( routes = static_route_names_output ) 
        static_route_gateways = obj.Networking.RouteTableV2.get_static_route_gateway( routes = static_route_names_output )

        print "%-20s" % "Destination" + "%-20s" % "Genmask" + "%-20s" % "Gateway"
        print "%-20s" % "-----------" + "%-20s" % "-------" + "%-20s" % "-------"
        for i in range(len(static_route_destinations)):
	    route = static_route_destinations[i]
            static_route_nets.append( route['address'] )
            static_route_masks.append( route['netmask'] )
            static_route_gws.append(static_route_gateways[i])

            print   "%-20s" % route['address'] + \
                    "%-20s" % route['netmask'] + \
                    "%-20s" % static_route_gateways[i] 

        return ( static_route_nets, static_route_masks, static_route_gws )

    except:
        print "Get static Route config error. Check log."
        traceback.print_exc(file=sys.stdout)




def set_profile_enabled_state ( obj, value ):
    try:

        # Note using ProfileFastL4 but to create object but object is generic so can use with any profile
        enabled_state = obj.LocalLB.ProfileFastL4.typefactory.create('LocalLB.ProfileEnabledState')
        enabled_state.default_flag = bool(0)
        if value == 'enable':
            enabled_state.value = "STATE_ENABLED"
        if value == 'disable':
            enabled_state.value = "STATE_DISABLED"
        return enabled_state

    except:
        print "Set Enabled State error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_profile_mode ( obj, value ):
    try:

        # Note using ProfileFastL4 but to create object but object is generic so can use with any profile
        ProfileProfileMode = obj.LocalLB.ProfileHttp.typefactory.create('LocalLB.ProfileProfileMode')
        ProfileProfileMode.default_flag = bool(0)
        if value == 'enable':
            ProfileProfileMode.value = "PROFILE_MODE_ENABLED"
        if value == 'disable':
            ProfileProfileMode.value = "PROFILE_MODE_DISABLED"
        return ProfileProfileMode

    except:
        print "Set ProfileProfileMode error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_profile_ULong ( obj, value ):

    #Bunch of misc short defs for setting profile settings
    try:

        # Note using ProfileFastL4 but to create object but object is generic so can use with any profile
        profileUlong = obj.LocalLB.ProfileFastL4.typefactory.create('LocalLB.ProfileULong')
        profileUlong.default_flag = bool(0)
        if value == "pass":
            profileUlong.value = 65535
        else:
            profileUlong.value = value
        return profileUlong

    except:
        print "Set ProfileUlong State error. Check log."
        traceback.print_exc(file=sys.stdout)
                        
def set_profile_UShort ( obj, value ):

    #Bunch of misc short defs for setting profile settings
    try:

        # Note using ProfileFastL4 but to create object but object is generic so can use with any profile
        profileUShort = obj.LocalLB.ProfileFastL4.typefactory.create('LocalLB.ProfileUShort')
        profileUShort.default_flag = bool(0)
        profileUShort.value = value
        return profileUShort

    except:
        print "Set ProfileUShort State error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_ProfileHardwareAccelerationMode (obj, value):
    #Bunch of misc short defs for setting profile settings
    try:
        accel_mode = obj.LocalLB.ProfileFastL4.typefactory.create('LocalLB.ProfileHardwareAccelerationMode')
        accel_mode.default_flag = bool(0) 

        hw_accel_mode = obj.LocalLB.ProfileFastL4.typefactory.create('LocalLB.HardwareAccelerationMode')
        if value == 'none':
            accel_mode.value = hw_accel_mode.HW_ACCELERATION_MODE_NONE
        if value == 'assist':
            accel_mode.value = hw_accel_mode.HW_ACCELERATION_MODE_ASSIST
        if value == 'full':
            accel_mode.value = hw_accel_mode.HW_ACCELERATION_MODE_FULL

        return accel_mode

    except:
        print "Set ProfileHardwareAccelerationMode error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_ProfileTCPOptionMode (obj, value): 
    #Bunch of misc short defs for setting profile settings
    try:

        profile_tcp_congest_mode = obj.LocalLB.ProfileFastL4.typefactory.create('LocalLB.ProfileTCPOptionMode')
        profile_tcp_congest_mode.default_flag = bool(0)

        tcp_opt_mode = obj.LocalLB.ProfileFastL4.typefactory.create('LocalLB.TCPOptionMode')
        if value == 'preserve':
            profile_tcp_congest_mode.value = tcp_opt_mode.TCP_OPTION_MODE_PRESERVE
        if value == 'rewrite':
            profile_tcp_congest_mode.value = tcp_opt_mode.TCP_OPTION_MODE_REWRITE
        if value == 'strip':
            profile_tcp_congest_mode.value = tcp_opt_mode.TCP_OPTION_MODE_STRIP

        return profile_tcp_congest_mode

    except:
        print "Set ProfileTCPOptionMode error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_ProfileTCPCongestionControlMode (obj, value): 
    #Bunch of misc short defs for setting profile settings
    try:

        profile_tcp_congest_mode = obj.LocalLB.ProfileTCP.typefactory.create('LocalLB.ProfileTCPCongestionControlMode')
        profile_tcp_congest_mode.default_flag = bool(0)

        tcp_congest_mode = obj.LocalLB.ProfileTCP.typefactory.create('LocalLB.TCPCongestionControlMode')
        if value == 'highspeed':
            profile_tcp_congest_mode.value = tcp_congest_mode.TCP_CONGESTION_CONTROL_HIGHSPEED
        if value == 'newreno':
            profile_tcp_congest_mode.value = tcp_congest_mode.TCP_CONGESTION_CONTROL_NEWRENO
        if value == 'reno':
            profile_tcp_congest_mode.value = tcp_congest_mode.TCP_CONGESTION_CONTROL_RENO 
        if value == 'scalable':
            profile_tcp_congest_mode.value = tcp_congest_mode.TCP_CONGESTION_CONTROL_SCALABLE 
        if value == 'none':
            profile_tcp_congest_mode.value = tcp_congest_mode.TCP_CONGESTION_CONTROL_NONE

        return profile_tcp_congest_mode

    except:
        print "Set ProfileTCPOptionMode error. Check log."
        traceback.print_exc(file=sys.stdout)




def set_ProfileIPAddress ( obj, value ):


    try:

        ProfileIPAddress = obj.LocalLB.ProfileOneConnect.typefactory.create('LocalLB.ProfileIPAddress')
        ProfileIPAddress.default_flag = bool(0)
        ProfileIPAddress.value = value

        return ProfileIPAddress

    except:
        print "Set ProfileIPAddress error. Check log."
        traceback.print_exc(file=sys.stdout)
                        


def set_ProfilePersistenceHashMethod(obj, value): 

    try:

        ProfilePersistenceHashMethod = obj.LocalLB.ProfilePersistence.typefactory.create('LocalLB.ProfilePersistence.ProfilePersistenceHashMethod')
        ProfilePersistenceHashMethod.default_flag = bool(0)

        PersistenceHashMethod = obj.LocalLB.ProfilePersistence.typefactory.create('LocalLB.ProfilePersistence.PersistenceHashMethod')
        if value == 'default':
            ProfilePersistenceHashMethod.value = PersistenceHashMethod.PERSISTENCE_HASH_DEFAULT
        if value == 'carp':
            ProfilePersistenceHashMethod.value = PersistenceHashMethod.PERSISTENCE_HASH_CARP
        if value == 'none':
            ProfilePersistenceHashMethod.value = PersistenceHashMethod.PERSISTENCE_HASH_NONE 

        return ProfilePersistenceHashMethod

    except:
        print "Set ProfilePersistenceHashMethod error. Check log."
        traceback.print_exc(file=sys.stdout)



def set_fastl4_profile (obj, name, dict ):

# Profile Defaults:
# profile fastL4 my_fastL4 {
   # defaults from fastL4
   # reset on timeout enable
   # reassemble fragments disable
   # idle timeout 300
   # tcp handshake timeout 5
   # tcp close timeout 5
   # mss override 0
   # tcp timestamp preserve
   # tcp wscale preserve
   # tcp generate isn disable
   # tcp strip sack disable
   # ip tos to client pass
   # ip tos to server pass
   # link qos to client pass
   # link qos to server pass
   # rtt from client disable
   # rtt from server disable
   # loose initiation disable
   # loose close disable
   # software syncookie disable
   # tcp keep alive interval 0
# }


    try:

        obj.LocalLB.ProfileFastL4.create( profile_names = [ name ] )

        for key,value in dict.items():
            if key == 'defaults from':
                obj.LocalLB.ProfileFastL4.set_default_profile( profile_names = [ name ], defaults = [ value ] )
            elif key == 'idle timeout':
                profileUlong = set_profile_ULong ( obj, value )
                obj.LocalLB.ProfileFastL4.set_idle_timeout( profile_names = [ name ], timeouts = [ profileUlong ] ) 
            elif key == 'reset on timeout':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_reset_on_timeout_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'loose initiation':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_loose_initiation_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'loose close':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_loose_close_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'pva acceleration':
                accel_mode = set_ProfileHardwareAccelerationMode (obj, value)
                obj.LocalLB.ProfileFastL4.set_hardware_acceleration_mode( profile_names = [ name ], acceleration_modes = [ accel_mode ] )
            elif key == 'hardware syncookie':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_hardware_syn_cookie_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'reassemble fragments':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_ip_fragment_reassemble_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'ip tos to client':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileFastL4.set_ip_tos_to_client( profile_names = [ name ], ip_tos_values = [ profileUlong ] )
            elif key == 'ip tos to server':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileFastL4.set_ip_tos_to_server( profile_names = [ name ], ip_tos_values = [ profileUlong ] )
            elif key == 'tcp keep alive interval':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileFastL4.set_keep_alive_interval( profile_names = [ name ], intervals = [ profileUlong ] )
            elif key == 'link qos to client':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileFastL4.set_link_qos_to_client( profile_names = [ name ], link_qos_values = [ profileUlong ] )
            elif key == 'link qos to server':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileFastL4.set_link_qos_to_server( profile_names = [ name ], link_qos_values = [ profileUlong ] )
            elif key == 'mss override':
                profileUlong = set_profile_ULong ( obj, value )
                obj.LocalLB.ProfileFastL4.set_mss_override( profile_names = [ name ], mss_overrides = [ profileUlong ] )
            elif key == 'rtt from client':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_rtt_from_client_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'rtt from server':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_rtt_from_server_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'software syncookie':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_software_syn_cookie_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'tcp close timeout':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileFastL4.set_tcp_close_timeout( profile_names = [ name ], timeouts = [ profileUlong ] ) 
            elif key == 'tcp generate isn':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_tcp_generate_isn_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'tcp handshake timeout':
                profileUlong = set_profile_ULong ( obj, value )
                obj.LocalLB.ProfileFastL4.set_tcp_handshake_timeout( profile_names = [ name ], timeouts = [ profileUlong ] ) 
            elif key == 'tcp strip sack':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileFastL4.set_tcp_strip_sackok_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'tcp timestamp':
                tcp_opt_mode = set_ProfileTCPOptionMode(obj, value)
                obj.LocalLB.ProfileFastL4.set_tcp_timestamp_mode( profile_names = [ name ], modes = [ tcp_opt_mode ] )
            elif key == 'tcp wscale':
                tcp_opt_mode = set_ProfileTCPOptionMode(obj, value)
                obj.LocalLB.ProfileFastL4.set_tcp_window_scale_mode( profile_names = [ name ], modes = [ tcp_opt_mode ] )

    except:
        print "Create FastL4 Profile error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_fastl4_profile (obj, name ):
    try:
        if not name:
            profile_names = obj.LocalLB.ProfileFastL4.get_list()
        else:
            profile_names = [ name ]
        
        default_profiles = obj.LocalLB.ProfileFastL4.get_default_profile( profile_names = profile_names ) 
        idle_timeout_profileUlong = obj.LocalLB.ProfileFastL4.get_idle_timeout( profile_names = profile_names ) 
        reset_on_timeout_enabled_state = obj.LocalLB.ProfileFastL4.get_reset_on_timeout_state( profile_names = profile_names )
        loose_init_enabled_state = obj.LocalLB.ProfileFastL4.get_loose_initiation_state( profile_names = profile_names )
        loose_close_enabled_state = obj.LocalLB.ProfileFastL4.get_loose_close_state( profile_names = profile_names )
        hardware_accel_mode = obj.LocalLB.ProfileFastL4.get_hardware_acceleration_mode( profile_names = profile_names )
        hardware_syn_cookie_enabled_state = obj.LocalLB.ProfileFastL4.get_hardware_syn_cookie_state( profile_names = profile_names )
        ip_fragment_reassembl_enabled_state = obj.LocalLB.ProfileFastL4.get_ip_fragment_reassemble_state( profile_names = profile_names )
        ip_tos_to_client_profileUlong = obj.LocalLB.ProfileFastL4.get_ip_tos_to_client( profile_names = profile_names )
        ip_tos_to_server_profileUlong = obj.LocalLB.ProfileFastL4.get_ip_tos_to_server( profile_names = profile_names )
        keep_alive_interval_profileUlong = obj.LocalLB.ProfileFastL4.get_keep_alive_interval( profile_names = profile_names )
        link_qos_to_client_profileUlong = obj.LocalLB.ProfileFastL4.get_link_qos_to_client( profile_names = profile_names )
        link_qos_to_server_profileUlong = obj.LocalLB.ProfileFastL4.get_link_qos_to_server( profile_names = profile_names )
        mss_override_profileUlong = obj.LocalLB.ProfileFastL4.get_mss_override( profile_names = profile_names )
        rtt_from_client_enabled_state = obj.LocalLB.ProfileFastL4.get_rtt_from_client_state( profile_names = profile_names )
        rtt_from_server_enabled_state =  obj.LocalLB.ProfileFastL4.get_rtt_from_server_state( profile_names = profile_names )
        software_syn_cookie_enabled_state = obj.LocalLB.ProfileFastL4.get_software_syn_cookie_state( profile_names = profile_names )
        tcp_close_timeout_profileUlong = obj.LocalLB.ProfileFastL4.get_tcp_close_timeout( profile_names = profile_names ) 
        tcp_generate_isn_enabled_state = obj.LocalLB.ProfileFastL4.get_tcp_generate_isn_state( profile_names = profile_names )
        tcp_handshake_timeout_profileUlong = obj.LocalLB.ProfileFastL4.get_tcp_handshake_timeout( profile_names = profile_names ) 
        tcp_strip_sackok_enabled_state = obj.LocalLB.ProfileFastL4.get_tcp_strip_sackok_state( profile_names = profile_names )
        tcp_timestamp_tcp_opt_mode = obj.LocalLB.ProfileFastL4.get_tcp_timestamp_mode( profile_names = profile_names )
        tcp_window_scale_tcp_opt_mode = obj.LocalLB.ProfileFastL4.get_tcp_window_scale_mode( profile_names = profile_names )

        for i in range(len(profile_names)):
            print "Profile Name: \"%s\"" % profile_names[i]
            print "%-25s" % 'defaults from' + str(default_profiles[i])
            if not idle_timeout_profileUlong[i].default_flag:
                print "%-25s" % 'idle timeout' + str(idle_timeout_profileUlong[i].value)
            if not reset_on_timeout_enabled_state[i].default_flag: 
                print "%-25s" % 'reset on timeout' + str(reset_on_timeout_enabled_state[i].value)
            if not loose_init_enabled_state[i].default_flag: 
                print "%-25s" % 'loose initiation' + str(loose_init_enabled_state[i].value)
            if not loose_close_enabled_state[i].default_flag: 
                print "%-25s" % 'loose close' + str(loose_close_enabled_state[i].value)
            if not hardware_accel_mode[i].default_flag: 
                print "%-25s" % 'pva acceleration' + str(hardware_accel_mode[i].value)
            if not hardware_syn_cookie_enabled_state[i].default_flag: 
                print "%-25s" % 'hardware syncookie' + str(hardware_syn_cookie_enabled_state[i].value)
            if not ip_fragment_reassembl_enabled_state[i].default_flag: 
                print "%-25s" % 'reassemble fragments' + str(ip_fragment_reassembl_enabled_state[i].value)
            if not ip_tos_to_client_profileUlong[i].default_flag: 
                print "%-25s" % 'ip tos to client' + str(ip_tos_to_client_profileUlong[i].value)
            if not ip_tos_to_server_profileUlong[i].default_flag: 
                print "%-25s" % 'ip tos to server' + str(ip_tos_to_server_profileUlong[i].value)
            if not keep_alive_interval_profileUlong[i].default_flag: 
                print "%-25s" % 'tcp keep alive interval' + str(keep_alive_interval_profileUlong[i].value)
            if not link_qos_to_client_profileUlong[i].default_flag: 
                print "%-25s" % 'ip qos to client' + str(link_qos_to_client_profileUlong[i].value)
            if not link_qos_to_server_profileUlong[i].default_flag: 
                print "%-25s" % 'ip qos to server' + str(link_qos_to_server_profileUlong[i].value)
            if not mss_override_profileUlong[i].default_flag: 
                print "%-25s" % 'mss override' + str(mss_override_profileUlong[i].value)
            if not rtt_from_client_enabled_state[i].default_flag: 
                print "%-25s" % 'rtt from client' + str(rtt_from_client_enabled_state[i].value)
            if not rtt_from_server_enabled_state[i].default_flag: 
                print "%-25s" % 'rtt from server' + str(rtt_from_server_enabled_state[i].value)
            if not software_syn_cookie_enabled_state[i].default_flag: 
                print "%-25s" % 'software syncookie' + str(software_syn_cookie_enabled_state[i].value)
            if not tcp_close_timeout_profileUlong[i].default_flag: 
                print "%-25s" % 'tcp close timeout' + str(tcp_close_timeout_profileUlong[i].value)
            if not tcp_generate_isn_enabled_state[i].default_flag: 
                print "%-25s" % 'tcp generate isn' + str(tcp_generate_isn_enabled_state[i].value)
            if not tcp_handshake_timeout_profileUlong[i].default_flag: 
                print "%-25s" % 'tcp handshake timeout' + str(tcp_handshake_timeout_profileUlong[i].value)
            if not tcp_strip_sackok_enabled_state[i].default_flag: 
                print "%-25s" % 'tcp strip sack' + str(tcp_strip_sackok_enabled_state[i].value)
            if not tcp_timestamp_tcp_opt_mode[i].default_flag: 
                print "%-25s" % 'tcp timestamp' + str(tcp_timestamp_tcp_opt_mode[i].value)
            if not tcp_window_scale_tcp_opt_mode[i].default_flag: 
                print "%-25s" % 'tcp wscale' + str(tcp_window_scale_tcp_opt_mode[i].value)

    except:
        print "Get FastL4 Profile error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_tcp_profile (obj, name, dict ):

# TCP Profile Defaults
# profile tcp my_tcp {
   # defaults from tcp
   # reset on timeout enable
   # time wait recycle enable
   # delayed acks enable
   # proxy mss disable
   # proxy options disable
   # deferred accept disable
   # selective acks enable
   # dsack disable
   # ecn disable
   # limited transmit enable
   # rfc1323 enable
   # slow start enable
   # bandwidth delay enable
   # nagle enable
   # abc enable
   # ack on push disable
   # verified accept disable
   # pkt loss ignore rate 0
   # pkt loss ignore burst 0
   # md5 sign disable
   # cmetrics cache enable
   # md5 sign passphrase none
   # proxy buffer low 4096
   # proxy buffer high 16384
   # idle timeout 300
   # time wait 2000
   # fin wait 5
   # close wait 5
   # send buffer 32768
   # recv window 32768
   # keep alive interval 1800
   # max retrans syn 3
   # max retrans 8
   # ip tos 0
   # link qos 0
   # congestion control highspeed
   # zero window timeout 20000
# }

    try:
        obj.LocalLB.ProfileTCP.create( profile_names = [ name ] )

        for key,value in dict.items():
            if key == 'defaults from':
                obj.LocalLB.ProfileTCP.set_default_profile( profile_names = [ name ], defaults = [ value ] )
            elif key == 'reset on timeout':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_reset_on_timeout_state ( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'time wait recycle':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_time_wait_recycle_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'delayed acks':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_delayed_ack_state ( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'proxy mss':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_proxy_mss_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'proxy options':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_proxy_option_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'deferred accept':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_deferred_accept_state ( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'selective acks':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_selective_ack_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'dsack':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_duplicate_selective_ack_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'ecn':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_ecn_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'limited transmit':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_limited_transmit_recovery_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'rfc1323':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_high_performance_tcp_extension_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'slow start':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_slow_start_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'bandwidth delay':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_bandwidth_delay_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'nagle':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_use_nagle_algorithm_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'abc':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_appropriate_byte_counting_state ( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'ack on push':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_ack_on_push_state( profile_names = [ name ], states = [ enabled_state ] ) 
            elif key == 'verified accept':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_verified_accept_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'pkt loss ignore rate':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_packet_loss_ignore_rate( profile_names = [ name ], thresholds = [ profileUlong ] )
            elif key == 'pkt loss ignore burst':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_packet_loss_ignore_burst( profile_names = [ name ], thresholds = [ profileUlong ] )
            elif key == 'md5 sign':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileTCP.set_md5_signature_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'md5 sign passphrase':
                obj.LocalLB.ProfileTCP.set_md5_signature_passphrase( profile_names = [ name ], passphrases = [ value ] )
            elif key == 'proxy buffer low':
                profileUlong = set_profile_ULong( obj, value )  
                obj.LocalLB.ProfileTCP.set_proxy_buffer_low( profile_names = [ name ], levels = [ profileUlong ] )
            elif key == 'proxy buffer high':
                profileUlong = set_profile_ULong( obj, value )  
                obj.LocalLB.ProfileTCP.set_proxy_buffer_high( profile_names = [ name ], levels = [ profileUlong ] )
            elif key == 'idle timeout':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_idle_timeout( profile_names = [ name ], timeouts = [ profileUlong ] )
            elif key == 'time wait':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_time_wait_timeout ( profile_names = [ name ], timeouts = [ profileUlong ] )
            elif key == 'fin wait':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_fin_wait_timeout( profile_names = [ name ], timeouts = [ profileUlong ] )
            elif key == 'close wait':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_close_wait_timeout( profile_names = [ name ], timeouts = [ profileUlong ] )
            elif key == 'send buffer':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_send_buffer_size( profile_names = [ name ], sizes = [ profileUlong ] )
            elif key == 'recv window':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_receive_window_size ( profile_names = [ name ], sizes = [ profileUlong ] )
            elif key == 'keep alive interval':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_keep_alive_interval( profile_names = [ name ], intervals = [ profileUlong ] )
            elif key == 'max retrans syn':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_maximum_syn_retransmission ( profile_names = [ name ], retries = [ profileUlong ] )
            elif key == 'max retrans':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_maximum_data_retransmission( profile_names = [ name ], retries = [ profileUlong ] )
            elif key == 'ip tos':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_ip_tos_to_client( profile_names = [ name ], values = [ profileUlong ] )
            elif key == 'link qos':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileTCP.set_link_qos_to_client( profile_names = [ name ], values = [ profileUlong ] )
            elif key == 'congestion control':
                ProfileTCPCongestionControlMode = set_ProfileTCPCongestionControlMode ( obj, value )  
                obj.LocalLB.ProfileTCP.set_congestion_control_mode( profile_names = [ name ], values = [ ProfileTCPCongestionControlMode ] )

   # zero window timeout 20000 # only in v11.0.0
        
   
    except:
        print "Create TCP Profile error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_tcp_profile (obj, name):
    try:
        if not name:
            profile_names = obj.LocalLB.ProfileTCP.get_list()
        else:
            profile_names = [ name ]

        default_profiles = obj.LocalLB.ProfileTCP.get_default_profile( profile_names = profile_names ) 
        reset_on_timeout_enabled_state = obj.LocalLB.ProfileTCP.get_reset_on_timeout_state ( profile_names = profile_names )  
        time_wait_recycle_enabled_state = obj.LocalLB.ProfileTCP.get_time_wait_recycle_state( profile_names = profile_names )  
        delayed_ack_enabled_state = obj.LocalLB.ProfileTCP.get_delayed_ack_state ( profile_names = profile_names )  
        proxy_mss_enabled_state = obj.LocalLB.ProfileTCP.get_proxy_mss_state( profile_names = profile_names )  
        proxy_option_enabled_state = obj.LocalLB.ProfileTCP.get_proxy_option_state( profile_names = profile_names )  
        deferred_accept_enabled_state = obj.LocalLB.ProfileTCP.get_deferred_accept_state ( profile_names = profile_names )  
        selective_ack_enabled_state = obj.LocalLB.ProfileTCP.get_selective_ack_state( profile_names = profile_names )  
        duplicate_selective_ack_enabled_state = obj.LocalLB.ProfileTCP.get_duplicate_selective_ack_state( profile_names = profile_names )  
        ecn_enabled_state = obj.LocalLB.ProfileTCP.get_ecn_state( profile_names = profile_names )  
        limited_transmit_recovery_enabled_state = obj.LocalLB.ProfileTCP.get_limited_transmit_recovery_state( profile_names = profile_names )  
        high_performance_tcp_extension_enabled_state = obj.LocalLB.ProfileTCP.get_high_performance_tcp_extension_state( profile_names = profile_names )  
        slow_start_enabled_state = obj.LocalLB.ProfileTCP.get_slow_start_state( profile_names = profile_names )  
        bandwidth_delay_enabled_state = obj.LocalLB.ProfileTCP.get_bandwidth_delay_state( profile_names = profile_names )  
        use_nagle_algorithm_enabled_state = obj.LocalLB.ProfileTCP.get_use_nagle_algorithm_state( profile_names = profile_names )  
        appropriate_byte_counting_enabled_state = obj.LocalLB.ProfileTCP.get_appropriate_byte_counting_state ( profile_names = profile_names )  
        ack_on_push_enabled_state = obj.LocalLB.ProfileTCP.get_ack_on_push_state( profile_names = profile_names )  
        verified_accept_enabled_state = obj.LocalLB.ProfileTCP.get_verified_accept_state( profile_names = profile_names )  
        packet_loss_ignore_rate_profileUlong = obj.LocalLB.ProfileTCP.get_packet_loss_ignore_rate( profile_names = profile_names )  
        packet_loss_ignore_burst_profileUlong = obj.LocalLB.ProfileTCP.get_packet_loss_ignore_burst( profile_names = profile_names )  
        md5_signature_enabled_state = obj.LocalLB.ProfileTCP.get_md5_signature_state( profile_names = profile_names )  
        md5_signature_strings = obj.LocalLB.ProfileTCP.get_md5_signature_passphrase( profile_names = profile_names )  
        proxy_buffer_low_profileUlong = obj.LocalLB.ProfileTCP.get_proxy_buffer_low( profile_names = profile_names )  
        proxy_buffer_high_profileUlong = obj.LocalLB.ProfileTCP.get_proxy_buffer_high( profile_names = profile_names )  
        idle_timeout_profileUlong = obj.LocalLB.ProfileTCP.get_idle_timeout( profile_names = profile_names )  
        time_wait_timeout_profileUlong = obj.LocalLB.ProfileTCP.get_time_wait_timeout ( profile_names = profile_names )  
        fin_wait_timeout_profileUlong = obj.LocalLB.ProfileTCP.get_fin_wait_timeout( profile_names = profile_names )  
        close_wait_timeout_profileUlong = obj.LocalLB.ProfileTCP.get_close_wait_timeout( profile_names = profile_names )  
        send_buffer_profileUlong = obj.LocalLB.ProfileTCP.get_send_buffer_size( profile_names = profile_names )  
        receive_window_size_profileUlong = obj.LocalLB.ProfileTCP.get_receive_window_size ( profile_names = profile_names )  
        keep_alive_interval_profileUlong = obj.LocalLB.ProfileTCP.get_keep_alive_interval( profile_names = profile_names )  
        maximum_syn_retransmission_profileUlong = obj.LocalLB.ProfileTCP.get_maximum_syn_retransmission ( profile_names = profile_names )  
        maximum_data_retransmission_profileUlong = obj.LocalLB.ProfileTCP.get_maximum_data_retransmission( profile_names = profile_names )  
        ip_tos_to_client_profileUlong = obj.LocalLB.ProfileTCP.get_ip_tos_to_client( profile_names = profile_names )  
        link_qos_to_client_profileUlong = obj.LocalLB.ProfileTCP.get_link_qos_to_client( profile_names = profile_names )  
        congestion_control_ProfileTCPCongestionControlMode = obj.LocalLB.ProfileTCP.get_congestion_control_mode( profile_names = profile_names )  

        for i in range(len(profile_names)):
            print "Profile Name: \"%s\"" % profile_names[i]
            print "%-25s" % 'defaults from' + str(default_profiles[i])
            if not reset_on_timeout_enabled_state[i].default_flag:
                print "%-25s" % 'reset on timeout' + str( reset_on_timeout_enabled_state[i].value )
            if not time_wait_recycle_enabled_state[i].default_flag:
                print "%-25s" % 'time wait recycle' + str( time_wait_recycle_enabled_state[i].value )
            if not delayed_ack_enabled_state[i].default_flag:
                print "%-25s" % 'delayed acks' + str( delayed_ack_enabled_state[i].value )
            if not proxy_mss_enabled_state[i].default_flag:
                print "%-25s" % 'proxy mss' + str( proxy_mss_enabled_state[i].value )
            if not proxy_option_enabled_state[i].default_flag:
                print "%-25s" % 'proxy options' + str( proxy_option_enabled_state[i].value )
            if not deferred_accept_enabled_state[i].default_flag:
                print "%-25s" % 'deferred accept' + str( deferred_accept_enabled_state[i].value )
            if not selective_ack_enabled_state[i].default_flag:
                print "%-25s" % 'selective acks' + str( selective_ack_enabled_state[i].value )
            if not duplicate_selective_ack_enabled_state[i].default_flag:
                print "%-25s" % 'dsack' + str( duplicate_selective_ack_enabled_state[i].value )
            if not ecn_enabled_state[i].default_flag:
                print "%-25s" % 'ecn' + str( ecn_enabled_state[i].value )
            if not limited_transmit_recovery_enabled_state[i].default_flag:
                print "%-25s" % 'limited transmit' + str( limited_transmit_recovery_enabled_state[i].value )
            if not high_performance_tcp_extension_enabled_state[i].default_flag:
                print "%-25s" % 'rfc1323' + str( high_performance_tcp_extension_enabled_state[i].value )
            if not slow_start_enabled_state[i].default_flag:
                print "%-25s" % 'slow start' + str( slow_start_enabled_state[i].value )
            if not bandwidth_delay_enabled_state[i].default_flag:
                print "%-25s" % 'bandwidth delay' + str( bandwidth_delay_enabled_state[i].value )
            if not use_nagle_algorithm_enabled_state[i].default_flag:
                print "%-25s" % 'nagle' + str( use_nagle_algorithm_enabled_state[i].value )
            if not appropriate_byte_counting_enabled_state[i].default_flag:
                print "%-25s" % 'abc' + str( appropriate_byte_counting_enabled_state[i].value )
            if not ack_on_push_enabled_state[i].default_flag:
                print "%-25s" % 'ack on push' + str( ack_on_push_enabled_state[i].value )
            if not verified_accept_enabled_state[i].default_flag:
                print "%-25s" % 'verified accept' + str( verified_accept_enabled_state[i].value )
            if not packet_loss_ignore_rate_profileUlong[i].default_flag:
                print "%-25s" % 'pkt loss ignore rate' + str( packet_loss_ignore_rate_profileUlong[i].value )
            if not packet_loss_ignore_burst_profileUlong[i].default_flag:
                print "%-25s" % 'pkt loss ignore burst' + str( packet_loss_ignore_burst_profileUlong[i].value )
            if not md5_signature_enabled_state[i].default_flag:
                print "%-25s" % 'md5 sign' + str( md5_signature_enabled_state[i].value )
            if not md5_signature_strings[i].default_flag:
                print "%-25s" % 'md5 sign passphrase' + str( md5_signature_strings[i].value )
            if not proxy_buffer_low_profileUlong[i].default_flag:
                print "%-25s" % 'proxy buffer low' + str( proxy_buffer_low_profileUlong[i].value )
            if not proxy_buffer_high_profileUlong[i].default_flag:
                print "%-25s" % 'proxy buffer high' + str( proxy_buffer_high_profileUlong[i].value )
            if not idle_timeout_profileUlong[i].default_flag:
                print "%-25s" % 'idle timeout' + str( idle_timeout_profileUlong[i].value )
            if not time_wait_timeout_profileUlong[i].default_flag:
                print "%-25s" % 'time wait' + str( time_wait_timeout_profileUlong[i].value )
            if not fin_wait_timeout_profileUlong[i].default_flag:
                print "%-25s" % 'fin wait' + str( fin_wait_timeout_profileUlong[i].value )
            if not close_wait_timeout_profileUlong[i].default_flag:
                print "%-25s" % 'close wait' + str( close_wait_timeout_profileUlong[i].value )
            if not send_buffer_profileUlong[i].default_flag:
                print "%-25s" % 'send buffer' + str( send_buffer_profileUlong[i].value )
            if not receive_window_size_profileUlong[i].default_flag:
                print "%-25s" % 'recv window' + str( receive_window_size_profileUlong[i].value )
            if not keep_alive_interval_profileUlong[i].default_flag:
                print "%-25s" % 'keep alive interval' + str( keep_alive_interval_profileUlong[i].value )
            if not maximum_syn_retransmission_profileUlong[i].default_flag:
                print "%-25s" % 'max retrans syn' + str( maximum_syn_retransmission_profileUlong[i].value )
            if not maximum_data_retransmission_profileUlong[i].default_flag:
                print "%-25s" % 'max retrans' + str( maximum_data_retransmission_profileUlong[i].value )
            if not ip_tos_to_client_profileUlong[i].default_flag:
                print "%-25s" % 'ip tos' + str( ip_tos_to_client_profileUlong[i].value )
            if not link_qos_to_client_profileUlong[i].default_flag:
                print "%-25s" % 'link qos' + str( link_qos_to_client_profileUlong[i].value )
            if not congestion_control_ProfileTCPCongestionControlMode[i].default_flag:
                print "%-25s" % 'congestion control' + str( congestion_control_ProfileTCPCongestionControlMode[i].value )
 

    except:
        print "Get TCP Profile error. Check log."
        traceback.print_exc(file=sys.stdout)




def set_udp_profile (obj, name, dict ):

# UDP Profile Defaults
# profile udp my_udp {
   # defaults from udp
   # idle timeout 60
   # ip tos 0
   # link qos 0
   # datagram lb disable
   # allow no payload disable
# }


    try:
        obj.LocalLB.ProfileUDP.create( profile_names = [ name ] )

        for key,value in dict.items():
            if key == 'defaults from':
                obj.LocalLB.ProfileUDP.set_default_profile( profile_names = [ name ], defaults = [ value ] )
            elif key == 'idle timeout':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileUDP.set_idle_timeout( profile_names = [ name ], timeouts = [ profileUlong ] )
            elif key == 'ip tos':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileUDP.set_ip_tos_to_client( profile_names = [ name ], values = [ profileUlong ] )
            elif key == 'link qos':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileUDP.set_link_qos_to_client( profile_names = [ name ], values = [ profileUlong ] )
            elif key == 'datagram lb':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileUDP.set_datagram_lb_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'allow no payload':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfileUDP.set_allow_no_payload_state( profile_names = [ name ], states = [ enabled_state ] )

    except:
        print "Create UDP Profile error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_udp_profile (obj, name):
    try:
        if not name:
            profile_names = obj.LocalLB.ProfileUDP.get_list()
        else:
            profile_names = [ name ]

        default_profiles = obj.LocalLB.ProfileUDP.get_default_profile( profile_names = profile_names ) 
        idle_timeout_profileUlong = obj.LocalLB.ProfileUDP.get_idle_timeout( profile_names = profile_names )
        ip_tos_to_client_profileUlong = obj.LocalLB.ProfileUDP.get_ip_tos_to_client( profile_names = profile_names )
        link_qos_to_client_profileUlong = obj.LocalLB.ProfileUDP.get_link_qos_to_client( profile_names = profile_names )
        datagram_lb_enabled_state = obj.LocalLB.ProfileUDP.get_datagram_lb_state( profile_names = profile_names )
        allow_no_payload_enabled_state = obj.LocalLB.ProfileUDP.get_allow_no_payload_state( profile_names = profile_names )

        for i in range(len(profile_names)):
            print "Profile Name: \"%s\"" % profile_names[i]
            print "%-25s" % 'defaults from' + str(default_profiles[i])
            if not idle_timeout_profileUlong[i].default_flag:
                print "%-25s" % 'idle timeout' + str( idle_timeout_profileUlong[i].value )
            if not ip_tos_to_client_profileUlong[i].default_flag:
                print "%-25s" % 'ip tos' + str( ip_tos_to_client_profileUlong[i].value )
            if not link_qos_to_client_profileUlong[i].default_flag:
                print "%-25s" % 'link qos' + str( link_qos_to_client_profileUlong[i].value )
            if not datagram_lb_enabled_state[i].default_flag:
                print "%-25s" % 'datagram lb' + str( datagram_lb_enabled_state[i].value )
            if not allow_no_payload_enabled_state[i].default_flag:
                print "%-25s" % 'allow no payload' + str( allow_no_payload_enabled_state[i].value )

    except:
        print "Get UDP Profile error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_http_profile (obj, name, dict ):

# Due to time contstraints, am not implementing whole thing.

# HTTP Profile Defaults
# profile http my_http {
   # defaults from http
   # basic auth realm none
   # oneconnect transformations enable
   # header insert none
   # header erase none
   # fallback none
   # compress disable
   # compress prefer gzip
   # compress min size 1024
   # compress buffer size 4096
   # compress vary header enable
   # compress http 1.0 disable
   # compress gzip memory level 8k
   # compress gzip window size 16k
   # compress gzip level 1
   # compress keep accept encoding disable
   # compress browser workarounds disable
   # compress cpu saver enable
   # compress cpu saver high 90
   # compress cpu saver low 75
   # response selective chunk
   # lws width 80
   # lws separator none
   # redirect rewrite none
   # max header size 32768
   # max requests 0
   # pipelining enable
   # insert xforwarded for disable
   # ramcache disable
   # ramcache size 100mb
   # ramcache max entries 10000
   # ramcache max age 3600
   # ramcache min object size 500
   # ramcache max object size 50000
   # ramcache ignore client cache control all
   # ramcache aging rate 9
   # ramcache insert age header enable
   # security disable
   # fallback status none
   # response headers allowed none
   # encrypt cookies none
   # compress uri include none
   # compress uri exclude none
   # compress content type include {
      # "text/"
      # "application/(xml|x-javascript)"
   # }
   # compress content type exclude none
   # ramcache uri exclude none
   # ramcache uri include none
   # ramcache uri pinned none
# }




    try:
        obj.LocalLB.ProfileHttp.create( profile_names = [ name ] )

        for key,value in dict.items():
            if key == 'defaults from':
                obj.LocalLB.ProfileHttp.set_default_profile( profile_names = [ name ], defaults = [ value ] )
            elif key == 'insert xforwarded for':
                profile_mode = set_profile_mode ( obj, value )  
                obj.LocalLB.ProfileHttp.set_insert_xforwarded_for_header_mode( profile_names = [ name ], modes = [ profile_mode ] )

    except:
        print "Create HTTP Profile error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_http_profile (obj, name):
    try:
        if not name:
            profile_names = obj.LocalLB.ProfileHttp.get_list()
        else:
            profile_names = [ name ]

        default_profiles = obj.LocalLB.ProfileHttp.get_default_profile( profile_names = profile_names ) 
        insert_xforwarded_for_header_mode = obj.LocalLB.ProfileHttp.get_insert_xforwarded_for_header_mode( profile_names = profile_names )

        for i in range(len(profile_names)):
            print "Profile Name: \"%s\"" % profile_names[i]
            print "%-25s" % 'defaults from' + str(default_profiles[i])
            if not insert_xforwarded_for_header_mode[i].default_flag:
                print "%-25s" % 'insert xforwarded for' + str( insert_xforwarded_for_header_mode[i].value )

    except:
        print "Get HTTP Profile error. Check log."
        traceback.print_exc(file=sys.stdout)




def set_oneconnect_profile (obj, name, dict ):


# ONECONNECT Profile Defaults
# profile oneconnect my_oneconnect {
   # defaults from oneconnect
   # source mask 0.0.0.0
   # max size 10000
   # max age 86400
   # max reuse 1000
   # idle timeout override disable
# }


    try:
        obj.LocalLB.ProfileOneConnect.create( profile_names = [ name ] )

        for key,value in dict.items():
            if key == 'defaults from':
                obj.LocalLB.ProfileOneConnect.set_default_profile( profile_names = [ name ], defaults = [ value ] )
            elif key == 'source mask':
                ProfileIPAddress = set_ProfileIPAddress ( obj, value)
                obj.LocalLB.ProfileOneConnect.set_source_mask( profile_names = [ name ], source_masks = [ ProfileIPAddress ] )
            elif key == 'max size':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileOneConnect.set_maximum_connection( profile_names = [ name ], maximum_connections = [ profileUlong ] )
            elif key == 'max age':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileOneConnect.set_maximum_age( profile_names = [ name ], maximum_ages = [ profileUlong ] )
            elif key == 'max reuse':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileOneConnect.set_maximum_reuse( profile_names = [ name ], maximum_reuses = [ profileUlong ] )
            elif key == 'idle timeout override':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfileOneConnect.set_idle_timeout( profile_names = [ name ], timeouts = [ profileUlong ] )
    except:
        print "Create OneConnect Profile error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_oneconnect_profile (obj, name):
    try:
        if not name:
            profile_names = obj.LocalLB.ProfileOneConnect.get_list()
        else:
            profile_names = [ name ]

        default_profiles = obj.LocalLB.ProfileOneConnect.get_default_profile( profile_names = profile_names )
        source_mask_ProfileIPAddress = obj.LocalLB.ProfileOneConnect.get_source_mask( profile_names = profile_names )
        max_size_profileUlong = obj.LocalLB.ProfileOneConnect.get_maximum_connection( profile_names = profile_names )
        max_age_profileUlong = obj.LocalLB.ProfileOneConnect.get_maximum_age( profile_names = profile_names )
        max_reuse_profileUlong = obj.LocalLB.ProfileOneConnect.get_maximum_reuse( profile_names = profile_names )
        idle_timeout_override_profileUlong = obj.LocalLB.ProfileOneConnect.get_idle_timeout( profile_names = profile_names )

        for i in range(len(profile_names)):
            print "Profile Name: \"%s\"" % profile_names[i]
            print "%-25s" % 'defaults from' + str(default_profiles[i])
            if not source_mask_ProfileIPAddress[i].default_flag:
                print "%-25s" % 'source mask' + str( source_mask_ProfileIPAddress[i].value )
            if not max_size_profileUlong[i].default_flag:
                print "%-25s" % 'max size' + str( max_size_profileUlong[i].value )
            if not max_age_profileUlong[i].default_flag:
                print "%-25s" % 'max age' + str( max_age_profileUlong[i].value )
            if not max_reuse_profileUlong[i].default_flag:
                print "%-25s" % 'max reuse' + str( max_reuse_profileUlong[i].value )
            if not idle_timeout_override_profileUlong[i].default_flag:
                print "%-25s" % 'idle timeout override' + str( idle_timeout_override_profileUlong[i].value )

    except:
        print "Get OneConnect Profile error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_src_persist_profile (obj, name, dict ):

# Source Persist Defaults 
# profile persist my_source_persist {
   # defaults from source_addr
   # mode source addr
   # timeout 180
   # mask none
   # map proxies enable
   # hash alg default
   # across services disable
   # across virtuals disable
   # across pools disable
   # override connection limit disable
# }


    try:

        persist_type = obj.LocalLB.ProfilePersistence.typefactory.create('LocalLB.PersistenceMode')
        persist_mode = persist_type.PERSISTENCE_MODE_SOURCE_ADDRESS_AFFINITY

        obj.LocalLB.ProfilePersistence.create( profile_names = [ name ],  modes = [ persist_mode ] )

        for key,value in dict.items():
            if key == 'defaults from':
                obj.LocalLB.ProfilePersistence.set_default_profile( profile_names = [ name ], defaults = [ value ] )
            elif key == 'timeout':
                profileUlong = set_profile_ULong ( obj, value )  
                obj.LocalLB.ProfilePersistence.set_timeout( profile_names = [ name ], timeouts = [ profileUlong ] )
            elif key == 'mask':
                ProfileIPAddress = set_ProfileIPAddress ( obj, value)
                obj.LocalLB.ProfilePersistence.set_mask( profile_names = [ name ], masks = [ ProfileIPAddress ] )
            elif key == 'map proxies':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfilePersistence.set_map_proxy_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'hash alg':
                ProfilePersistenceHashMethod = set_ProfilePersistenceHashMethod ( obj, value )  
                obj.LocalLB.ProfilePersistence.set_hash_method( profile_names = [ name ], methods = [ ProfilePersistenceHashMethod ] )
            elif key == 'across services':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfilePersistence.set_across_service_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'across virtuals':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfilePersistence.set_across_virtual_state( profile_names = [ name ], states = [ enabled_state ] )
            elif key == 'across pools':
                enabled_state = set_profile_enabled_state ( obj, value )
                obj.LocalLB.ProfilePersistence.set_across_pool_state( profile_names = [ name ], states = [ enabled_state ] )
           # Not in 10.x yet
           # elif key == 'override connection limit':
                # enabled_state = set_profile_enabled_state ( obj, value )  
                # obj.LocalLB.ProfilePersistence.set_override_connection_limit_state( profile_names = [ name ], states = [ enabled_state ] )
    except:
        print "Create Persist Profile error. Check log."
        traceback.print_exc(file=sys.stdout)



def get_src_persist_profile (obj, name):
    try:
    
        profile_names = []

        if not name:
            #Try to only grab Source Addr Profiles
            all_persist_profiles = obj.LocalLB.ProfilePersistence.get_list()
            all_persist_profile_modes = obj.LocalLB.ProfilePersistence.get_persistence_mode( all_persist_profiles )
            for i in range(len(all_persist_profiles)):
                if all_persist_profile_modes[i].value == "PERSISTENCE_MODE_SOURCE_ADDRESS_AFFINITY":
                    profile_names.append(all_persist_profiles[i])
        
        else:
            profile_names = [ name ]

        default_profiles = obj.LocalLB.ProfilePersistence.get_default_profile( profile_names = profile_names )
        timeout_profileUlong = obj.LocalLB.ProfilePersistence.get_timeout( profile_names = profile_names )
        mask_ProfileIPAddress = obj.LocalLB.ProfilePersistence.get_mask( profile_names = profile_names )
        map_proxies_enabled_state = obj.LocalLB.ProfilePersistence.get_map_proxy_state( profile_names = profile_names )
        hash_alg_method = obj.LocalLB.ProfilePersistence.get_hash_method( profile_names = profile_names )
        across_services_enabled_state = obj.LocalLB.ProfilePersistence.get_across_service_state( profile_names = profile_names )
        across_virtuals_enabled_state = obj.LocalLB.ProfilePersistence.get_across_virtual_state( profile_names = profile_names )
        across_pools_enabled_state = obj.LocalLB.ProfilePersistence.get_across_pool_state( profile_names = profile_names )

        for i in range(len(profile_names)):
            print "Profile Name: \"%s\"" % profile_names[i]
            print "%-25s" % 'defaults from' + str(default_profiles[i])
            if not timeout_profileUlong[i].default_flag:
                print "%-25s" % 'timeout' + str( timeout_profileUlong[i].value )
            if not mask_ProfileIPAddress[i].default_flag:
                print "%-25s" % 'mask' + str( mask_ProfileIPAddress[i].value )
            if not map_proxies_enabled_state[i].default_flag:
                print "%-25s" % 'map proxies' + str( map_proxies_enabled_state[i].value )
            if not hash_alg_method[i].default_flag:
                print "%-25s" % 'hash alg' + str( hash_alg_method[i].value )
            if not across_services_enabled_state[i].default_flag:
                print "%-25s" % 'across services' + str( across_services_enabled_state[i].value )
            if not across_virtuals_enabled_state[i].default_flag:
                print "%-25s" % 'across virtuals' + str( across_virtuals_enabled_state[i].value )
            if not across_pools_enabled_state[i].default_flag:
                print "%-25s" % 'across pools' + str( across_pools_enabled_state[i].value )


    except:
        print "Get Persist Profile error. Check log."
        traceback.print_exc(file=sys.stdout)


def create_pool(obj, pool_names, pool_ips, pool_ports, lb_methods, monitors ):

    #Disclaimer. Only allows one monitor per pool

    try:

        pool_names_seq = []
        for pool_name in pool_names:
            pool_names_seq.append(pool_name)

        lb_methods_seq = []
        for lb_method in lb_methods:
            lb_methods_seq.append(lb_method) 

	ip_port_def_seq_seq = []
        for i in range(len(pool_ips)):
	    members = pool_ips[i]
	    ip_port_def_seq = [ ]
	    for j in range(len(members)):
		#print "pool_ports[i][j] is: " + str(pool_ports[i][j])
		ip_port_def = { 'address' : members[j] , 'port' : pool_ports[i][j] }
		ip_port_def_seq.append(ip_port_def)
	    ip_port_def_seq_seq.append(ip_port_def_seq)
	    

        obj.LocalLB.Pool.create_v2(
                                pool_names = pool_names_seq,
                                lb_methods = lb_methods_seq,
                                members = ip_port_def_seq_seq
                                )


        monitor_assoc_seq = [ ]
        for i in range(len(pool_names)):

            monitor_templates_seq = []
            monitor_templates_seq.append(monitors[i])
	    monitor_rule_obj = { 'type' : "MONITOR_RULE_TYPE_AND_LIST" , 'quorum': 1, 'monitor_templates' : monitor_templates_seq }  
            monitor_assoc_obj = { 'pool_name' : pool_names[i], 'monitor_rule' : monitor_rule_obj }
            monitor_assoc_seq.append(monitor_assoc_obj)

        obj.LocalLB.Pool.set_monitor_association( monitor_associations = monitor_assoc_seq )


    except:
        print "Create Pool error. Check log."
        traceback.print_exc(file=sys.stdout)




def get_pool( obj, pool_names ):
    
    # pool_ips, pool_ports, lb_methods, monitors
    try:

        if not pool_names:
            pool_name_seq = obj.LocalLB.Pool.get_list()
        else:
            pool_name_seq = pool_names

        lb_method_seq = obj.LocalLB.Pool.get_lb_method( pool_names = pool_name_seq )
        ip_port_def_seq_seq = obj.LocalLB.Pool.get_member( pool_names = pool_name_seq )
        monitor_seq = obj.LocalLB.Pool.get_monitor_association( pool_names = pool_name_seq )
        status_seq = obj.LocalLB.Pool.get_object_status( pool_names = pool_name_seq ) 

        for v in range(len(pool_name_seq)):
            print ""
            print "%-25s" % "Pool Name:"            + "%-25s" % pool_name_seq[v] 
            print "%-25s" % "----------------"      + "%-25s" % "----------------"
            print "%-25s" % "LB Method:"            + "%-25s" % lb_method_seq[v]
            print "%-25s" % "Monitor:"              + "%-25s" % monitor_seq[v]['monitor_rule']['monitor_templates']
            for m in range(len(ip_port_def_seq_seq[v])):
                print "%-25s" % "Member Address:"  + "%s" % ip_port_def_seq_seq[v][m]['address'] + \
                      ":%d" % ip_port_def_seq_seq[v][m]['port']
            print "%-25s" % "Pool Status:"           + "%-25s" % status_seq[v]['availability_status']



    except:
        print "Get Pool error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_irules( obj, names, definitions ):

    
    try:
	rule_definitions = []
        for i in range(len(names)):
	    rule_def = { 'rule_name' 	   : names[i], 
			 'rule_definition' : definitions[i] }
	    rule_definitions.append(rule_def)


        obj.LocalLB.Rule.create( rules = rule_definitions )

    except:
        print "iRule create error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_irules( obj, names ):

    
    try:
	    
	rule_def_seq = obj.LocalLB.Rule.query_rule( names )
        print "%-30s" % "Rule Name" + "%s" % "Definition"
        print "%-30s" % "-----"     + "%s" % "-----"
	
        for v in range(len(rule_def_seq)):
            print (
		    "%-30s" % rule_def_seq[v]['rule_name'].strip() + 
		      "%s"  % rule_def_seq[v]['rule_definition'].replace('\n','\n\t\t\t\t').strip()
		  )
	
	return rule_def_seq

    except:
        print "iRule get error. Check log."
        traceback.print_exc(file=sys.stdout)


def create_virtual_addresses(obj, virtual_networks, virtual_masks, traffic_groups, initial_states ):

	
    try:
		
        obj.LocalLB.VirtualAddressV2.create(
						    virtual_addresses = virtual_networks,
						    addresses = virtual_networks,
						    netmasks = virtual_masks
						)

        obj.LocalLB.VirtualAddressV2.set_enabled_state( 
							virtual_addresses = virtual_networks,
							states = initial_states
						      )
        obj.LocalLB.VirtualAddressV2.set_arp_state( 
							virtual_addresses = virtual_networks,
							states = initial_states
						  )
			

    except:
        print "Virtual Server Address create error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_virtual_addresses(obj, virtual_networks ):

    try:
	
	virtual_address_list = []
	virtual_address_states = []
	if len(virtual_networks) < 1:
	    virtual_address_list = virtual_networks 
	else:
	    virtual_address_list = obj.LocalLB.VirtualAddressV2.get_list()
	
        virtual_address_state = obj.LocalLB.VirtualAddressV2.get_enabled_state( virtual_addresses = virtual_address_list )

        print "%-30s" % "Virtual Address" + "%s" % "State"
        print "%-30s" % "---------------"     + "%s" % "_____"
	
        for v in range(len(virtual_address_list)):
            print (
		    "%-30s" % virtual_address_list[v] + 
		      "%s"  % virtual_address_state[v]  
		  )

    except:
        print "Get Virtual Server Address error. Check log."
        traceback.print_exc(file=sys.stdout)




def create_virtual_servers( obj, virtual_names, virtual_networks, virtual_ports, virtual_types , protocol_profiles, ssl_profiles, resources, virtual_pools ):
  
    try:

	virtual_defs = []
	wildmasks = []
	resources = []
	profiles = []
	for i in range(len(virtual_names)):
	    #Some hardcoding for now
	    virtual_def = { 
			    'name' 	: virtual_names[i],
			    'address' 	: virtual_networks[i],
			    'port' 	: virtual_ports[i],
			    'protocol' 	: "PROTOCOL_TCP"
			  }
	    virtual_defs.append(virtual_def)
	    wildmasks.append("255.255.255.255")
	    resource = { 
			'type' : "RESOURCE_TYPE_POOL",
			'default_pool_name' : virtual_pools[i]
			}
	    resources.append(resource)
	    virtual_profiles = []
	    if protocol_profiles[i]:
		profile = {
			    'profile_name' : "http",
			    'profile_context' : "PROFILE_CONTEXT_TYPE_ALL",
			  }
		virtual_profiles.append(profile)
	    else:
		virtual_profiles.append( { 'profile_name' : "tcp", 'profile_context' : "PROFILE_CONTEXT_TYPE_ALL" } )

	    if ssl_profiles[i]:
		"Client Profile exists with name " + ssl_profiles[i]
		profile = {
			    'profile_name' : "clientssl",
			    'profile_context' : "PROFILE_CONTEXT_TYPE_CLIENT",
			  }
		virtual_profiles.append(profile)
	    profiles.append(virtual_profiles)
		 
 
    
        obj.LocalLB.VirtualServer.create(
					    definitions = virtual_defs,
					    wildmasks = wildmasks,
					    resources = resources,
					    profiles = profiles
					)
	obj.LocalLB.VirtualServer.set_source_address_translation_automap(virtual_names)
    except:
        print "Virtual Server create error. Check log."
        traceback.print_exc(file=sys.stdout)


def save_config_to_disk (obj):

    try:

        #Save Base Config
        #save_mode = obj.System.ConfigSync.typefactory.create('System.ConfigSync.SaveMode')
        #obj.System.ConfigSync.save_configuration( filename = "/config/bigip.conf", save_flag = save_mode.SAVE_BASE_LEVEL_CONFIG" )
        obj.System.ConfigSync.save_configuration( filename = "/config/bigip_base.conf", save_flag = "SAVE_BASE_LEVEL_CONFIG"  )

        #Save High Config
        #obj.System.ConfigSync.save_configuration( filename = "/config/bigip.conf", save_flag = save_mode.SAVE_HIGH_LEVEL_CONFIG" )
        obj.System.ConfigSync.save_configuration( filename = "/config/bigip.conf", save_flag = "SAVE_HIGH_LEVEL_CONFIG"  )


    except:
        print "Save Config Error. Check log."
        traceback.print_exc(file=sys.stdout)

def save_base_config_to_disk (obj):

    try:

        #Save Base Config
        #save_mode = obj.System.ConfigSync.typefactory.create('System.ConfigSync.SaveMode')
        #obj.System.ConfigSync.save_configuration( filename = "/config/bigip.conf", save_flag = save_mode.SAVE_BASE_LEVEL_CONFIG" )
        obj.System.ConfigSync.save_configuration( filename = "/config/bigip_base.conf", save_flag = "SAVE_BASE_LEVEL_CONFIG"  )

    except:
        print "Save Config Error. Check log."
        traceback.print_exc(file=sys.stdout)


def save_high_config_to_disk (obj):

    try:

        #Save High Config
        #obj.System.ConfigSync.save_configuration( filename = "/config/bigip.conf", save_flag = save_mode.SAVE_HIGH_LEVEL_CONFIG" )
        obj.System.ConfigSync.save_configuration( filename = "/config/bigip.conf", save_flag = "SAVE_HIGH_LEVEL_CONFIG"  )

    except:
        print "Save Config Error. Check log."
        traceback.print_exc(file=sys.stdout)



def reboot_system (obj, secs ):
    try:

        obj.System.Services.reboot_system( seconds_to_reboot = long(secs) )

    except:
        print "Reboot Error. Check log."
        traceback.print_exc(file=sys.stdout)


def upload_file (obj, src_file_name, dest_file_name ):

    try:


        stream_io = io.open(src_file_name,'rb')

        preferred_chunk_size = 65536
        chunk_size = 65536
        total_bytes = 0
        foffset = 0
        poll = bool(1)

        file_chain_type = obj.System.ConfigSync.typefactory.create('Common.FileChainType')
        chain_type = file_chain_type.FILE_FIRST
        file_transfer_context = obj.System.ConfigSync.typefactory.create('System.ConfigSync.FileTransferContext')


        while poll:
            file_data = ""
            bytes_read = stream_io.read( preferred_chunk_size )

            if len(bytes_read) != preferred_chunk_size:
                if total_bytes == 0:
                    chain_type = file_chain_type.FILE_FIRST_AND_LAST
                else:
                    chain_type = file_chain_type.FILE_LAST
                poll = bool(0)
            
            total_bytes = total_bytes + len(bytes_read)
            file_transfer_context.file_data = base64.b64encode(bytes_read)
            file_transfer_context.chain_type = chain_type

            obj.System.ConfigSync.upload_file( file_name = dest_file_name, file_context = file_transfer_context )
            chain_type = file_chain_type.FILE_MIDDLE
            #print "Total Uploaded Bytes = %s " % total_bytes 
            


        print "Total Uploaded Bytes = %s " % total_bytes + " for filename %s" %  dest_file_name



    except:
        print "Upload File Error for file %s. Check log."  % src_file_name
        traceback.print_exc(file=sys.stdout)


def download_file (obj, remote_file, local_file ):

    try:

        stream_io = io.open(local_file,'wb')
        poll = True
        chunk_size = 65536
        foffset = 0
        lines = []

        while poll:
            res = obj.System.ConfigSync.download_file(file_name = remote_file, chunk_size = chunk_size, file_offset = foffset)
            foffset = long(res.file_offset)
            fdata = getattr(res,'return').file_data
            chain_type = getattr(res, 'return').chain_type
            lines.append(binascii.a2b_base64(fdata))
            if (chain_type == 'FILE_LAST') or (chain_type == 'FILE_FIRST_AND_LAST'):
                poll = False

        stream_io.writelines(lines)


    except:
        print "Download File Error. Check log."
        traceback.print_exc(file=sys.stdout)

def sync_group( obj, group_name, device_name, force_arg ):

    
    try:

	if re.match( r'True|force|1' , force_arg, re.IGNORECASE):
	    force = 1
	else:
	    force = 0
	obj.System.ConfigSync.synchronize_to_group_v2( 	
						    group = group_name, 
						   device = device_name,
						    force = force
					 )

    except:

        print "Error in Syncing Device Group Status. Check log."
        traceback.print_exc(file=sys.stdout)

def sync_group( obj, group_name, device_name, force_arg ):

    
    try:

	if re.match( r'True|force|1' , force_arg, re.IGNORECASE):
	    force = 1
	else:
	    force = 0
	obj.System.ConfigSync.synchronize_to_group_v2( 	
						    group = group_name, 
						   device = device_name,
						    force = force
					 )

    except:

        print "Error in Syncing Device Group Status. Check log."
        traceback.print_exc(file=sys.stdout)



# Couple of anonymous functions
# Note: Functions do not currently accept IPV6.
# Will need Socket v2.3 w/ socket.inet_pton & inet_ntop or another module like netaddr (v 0.7 or higher)
ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))

import os
import sys
import time
import struct
import socket
import traceback
import binascii
import base64
import io
import re
import urllib
import urllib2
import getpass
#Ones that not in standard lib
from suds.client import Client
from optparse import OptionParser
from configobj import ConfigObj
import bigsuds
#import pycontrol.pycontrol as pc
  
# from suds import WebFault
# import logging
# logging.getLogger('suds.client').setLevel(logging.DEBUG)
# logging.getLogger('suds.metrics').setLevel(logging.DEBUG)
# logging.getLogger('suds').setLevel(logging.DEBUG)

##########################    START MAIN LOGIC   #########################

def main():

    parser = OptionParser()
    parser.add_option("-b", "--bigip", action="store", type="string", dest="bigip")
    parser.add_option("-u", "--username", action="store", type="string", dest="username")
    parser.add_option("-c", "--config", action="store", type="string", dest="bigip_config_vars")
    (options, args) = parser.parse_args()

    print "bigip variables configuration file = " + options.bigip_config_vars + " !"


    ################### LOAD MOST OF CONFIG VARIABLES FROM FILE  ##############################
    # As BIGIP's configs are complex, really need to implement 
    # a more robust legitimate config parsing mechanism 
    # https://wiki.python.org/moin/ConfigParserShootout
    # for now, will use .ini style config and require the simple configobj module
    # http://www.voidspace.org.uk/python/configobj.html
    # which appears to be somewhat popular and preferred over builtin configparser module
    # ideally need to import xml + save in format similar to json calls 
    ###########################################################################################


    config = ConfigObj(options.bigip_config_vars)
    settings_dict = dict(config['SETTINGS'])

    # Potentially Make them availible globally
    # globals().update(settings_dict)  
    # print "global hostname is " + hostname

    if len(sys.argv) < 2:
	print "Usage %s config_file" % sys.argv[0]
	sys.exit()

    a = sys.argv[1:]

    bigip    = config['SETTINGS']['bigip']
    hostname = config['SETTINGS']['hostname']
    username = config['SETTINGS']['username']
    userpass = config['SETTINGS']['userpass']
    #print "\nHello %s, please enter your password below.\n" % options.username
    #userpass = getpass.getpass()

    #Now Initalize the bigsuds connection object
    try:   
	b = bigsuds.BIGIP(
	    hostname = bigip, 
	    username = username, 
	    password = userpass,
	    )
    except Exception, e:
	print e

############### START PROCESSING LOGIC  ##################

    
    #START CONFIGURING 
    print "\nGetting Hostname"
    get_hostname( b )
    

    ######### BEGIN TRAFFIC CONFIG  ################
     
    #Set Some Traffic Globals
    ltm_dict = dict(config['TRAFFIC']['LTM_GLOBALS'])
    #ltm_fields = ltm_dict
    ltm_fields = { 'max_reject_rate'     : ltm_dict['max_reject_rate'], 
		   'gratuitous_arp_rate' : ltm_dict['gratuitous_arp_rate'] } 

    print "\n\nSetting LTM Global Config: " 
    set_ltm_global_config( b, ltm_fields )
    print "\nGetting LTM Global Config: " 
    get_ltm_global_config( b, ltm_fields ) 

    #Set iRules
    irules_dict = dict(config['TRAFFIC']['IRULES'])
    irule_names = []
    irule_definitions = []
    for k,v in irules_dict.items():
	irule_names.append( k )
	irule_definitions.append( v['definition'] )

    print "\n\nSetting iRules: "
    set_irules( b, irule_names, irule_definitions )
    print "\nGetting iRules: "
    get_irules( b, irule_names )

    #Set Pools
    pool_dict = dict(config['TRAFFIC']['POOLS'])
    pool_names = []   
    pool_lb_methods = []
    pool_monitors = []
    pool_addresses = []
    pool_ports = []
    for k,v in pool_dict.items():
	pool_names.append( k )
	pool_lb_methods.append( v['lb_method'] )
	pool_monitors.append( [ v['monitor'] ] )
	pool_mem_dict = v['MEMBERS']
	my_addresses = []
	my_ports = []
	for k,v in pool_mem_dict.items():
	     #print "Key is: " + str(k) + " Value: " + str(v['address'])	     
	     my_addresses.append(v['address'])
	     my_ports.append(v['pool_port'])
	pool_addresses.append(my_addresses)
	pool_ports.append(my_ports)
     
    print "\n\nSetting Pools: "
    create_pool( b, pool_names, pool_addresses, pool_ports, pool_lb_methods, pool_monitors )
    print "\n\nGetting Pools: "
    get_pool( b, pool_names )

    #Create Virtual Addresses   
    virt_addr_dict = dict(config['TRAFFIC']['VIRTUAL_ADDRESSES'])
    virtual_address_names = []
    virtual_addresses = []
    virtual_masks = []
    traffic_groups = []
    initial_states = []
    for k,v in virt_addr_dict.items():
	virtual_address_names.append ( k )
	virtual_addresses.append ( v['address'] )
	virtual_masks.append ( v['mask'] )
	traffic_groups.append ( v['traffic_group'] )
	initial_states.append ( v['initial_state'] ) 
 
    #Create Virtuals 
    virtual_dict = dict(config['TRAFFIC']['VIRTUALS'])
    virtual_names = []
    virtual_networks = []
    virtual_ports = []
    virtual_types = []
    virtual_protocol_profiles = []
    virtual_ssl_profiles = []
    virtual_resources = []
    virtual_pools = []
    for k,v in virtual_dict.items():
	virtual_names.append( k )
	virtual_networks.append( v['network'] )
	virtual_ports.append( v['port'] )
	virtual_types.append( v['type'] )
	virtual_protocol_profiles.append( v['protocol_profiles'] )
	virtual_ssl_profiles.append( v['ssl_profiles'] )
	virtual_resources.append( v['resources'] )
	virtual_pools.append( v['pool'] )

    #Creating them all in a disabled state originally
    print "\n\nSetting Virtual Addresses"
    create_virtual_addresses(b, virtual_addresses, virtual_masks, traffic_groups, initial_states )
    print "\nGetting Virtual Addresses" 
    get_virtual_addresses(b, virtual_addresses ) 
    

    print "\n\nSetting Virtuals: "
    create_virtual_servers( b, virtual_names, virtual_networks, virtual_ports, virtual_types , virtual_protocol_profiles, virtual_ssl_profiles, virtual_resources, virtual_pools )
    # print "\nGetting Virtual Servers: "
    # get_virtuals (b, virtual_names )

    print "\n\nSaving Config to Disk..."
    save_config_to_disk (b)

    print "\nSyncing Failover Group"
    sync_group(b, "my_sync_failover_group" , hostname , "force" ) 

    print "\n\nFINISHED DEPLOYING APPLICATIONS!\n"
    # TO DO:
    # Deploy clientssl profiles
    # Deploy iApps instead


if __name__ == "__main__":
	main()




