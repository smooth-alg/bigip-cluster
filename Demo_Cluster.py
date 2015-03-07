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

NOTE: This script requires v11.5.0 and above as is using a new iControl call 

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

#   Possible Classes on v11.5.1
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



def generate_certificate( obj, cert_mode, cert_id, cert_email, hostname, cert_country, 
                          cert_state, cert_locality, cert_organization, cert_division, cert_expire ):

    try:

        mode = cert_mode
        certs = [ { 'id' : cert_id, 'email' : cert_email } ]
        x509_data = [ { 
			    'common_name' : hostname, 
			    'country_name' : cert_country, 
			    'state_name' : cert_state,
			    'locality_name' : cert_locality,
			    'organization_name' : cert_organization,
			    'division_name' : cert_division
			 }
		       ]
        lifetime_days = [ cert_expire ]
        overwrite = bool(1)

        obj.Management.KeyCertificate.certificate_generate( 
                                                            mode, 
                                                            certs,
                                                            x509_data,
                                                            lifetime_days,
                                                            overwrite 
                                                          );

    except:
        print "Generate Certificate Error. Check log."
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


def modify_db_keys ( obj, db_keys ):

    try:

        variables = []

        print "%-30s" % "key:" + "%s" % "value:"
        print "%-30s" % "----" + "%s" % "------"
	for i in range(len(db_keys)):
	    db_key = db_keys[i]
	    for k,v in db_key.items():
                print "%-30s" % k + "%s" % v
		db_key_obj = { 'name' : k, 'value' : v }
		variables.append( db_key_obj )
	    
        obj.Management.DBVariable.modify( variables )

    except:
        print "DB Key Change Error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_db_keys ( obj, variables ):
    try:

        query_output = obj.Management.DBVariable.query( variables )

        print "%-30s" % "key:" + "%s" % "value:"
        print "%-30s" % "----" + "%s" % "------"
        for i in range(len(query_output)):
                db_key = query_output[i]
                print "%-30s" % db_key['name'] + "%s" % db_key['value']
               
    except:
        print "DB Key Read Error. Check log."
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
	return hostname

    except:
        print "Get hostname error. Check log."
        traceback.print_exc(file=sys.stdout)


def install_certificate (obj, hostname ):

    try:

        print "Place holder"

    except:
        print "Install Certificate error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_self_ips( obj, names, addresses, netmasks, vlan_names, traffic_groups, floating_states, port_lock_down_list ):
    try:

        obj.Networking.SelfIPV2.create(
                                        self_ips = names,
					addresses = addresses,
                                        netmasks = netmasks,
                                        vlan_names = vlan_names,
                                        traffic_groups = traffic_groups,
                                        floating_states = floating_states
                                    )
# 
# 	access_list_seq = []    
#         for i in range(len(addresses)):
#             access_obj = {  'self_ip' 	: addresses[i], 
# 			    'mode'	: port_lock_down_list[i],
# 			    'protocol_ports' : [] 
# 			 }  
#             access_list_seq.append(access_obj)
# 
#         obj.Networking.SelfIPPortLockdown.add_allow_access_list( access_lists = access_list_seq )
#                

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
        #access_list_seq = obj.Networking.SelfIPPortLockdown.get_allow_access_list ( self_ip_seq )

        for v in range(len(self_ip_seq)):
            print ""
            print "%-25s" % "SelfIP:"               + "%-25s" % self_ip_seq[v] 
            print "%-25s" % "----------------"      + "%-25s" % "----------------"
            print "%-25s" % "Address:"              + "%-25s" % addresses_seq[v]
            print "%-25s" % "Netmask:"              + "%-25s" % netmasks_seq[v]
            print "%-25s" % "Vlan:"                 + "%-25s" % vlan_names_seq[v]
            print "%-25s" % "Traffic Group:"        + "%-25s" % traffic_group_seq[v]
            print "%-25s" % "Floating State:"       + "%-25s" % floating_states_seq[v]  
	    #print "%-25s" % "Port Lock Down Mode=>" + "%-25s" % access_list_seq[v]['mode']

	return ( {	'self_ip' 	: self_ip_seq , 
			'address' 	: addresses_seq , 
			'netmask' 	: netmasks_seq ,
			'vlan'	  	: vlan_names_seq ,
			'traffic_group' : traffic_group_seq ,
			'floating_state': floating_states_seq
		 })
    except:
        print "Get SelfIP config error. Check log."
        traceback.print_exc(file=sys.stdout)

def return_network_dot_quad ( ip, netmask ):

    # Takes dot quad ip and netmask string and returns network string
    # Note: Does not take IPV6. Would need Socket v2.3 w/ socket.inet_pton & inet_ntop
    # will replace with ipaddress module  
    try:
            ip_int = ip2int(ip)
            netmask_int = ip2int(netmask)
            ip_net_int = ip_int & netmask
            ip_net = int2ip(ip_net_int)
            return ip_net 

    except:
        print "Could not return network"



def save_config_to_disk (obj):

    try:

        #Save Base Config
        obj.System.ConfigSync.save_configuration( filename = "/config/bigip_base.conf", save_flag = "SAVE_BASE_LEVEL_CONFIG"  )

        #Save High Config
        obj.System.ConfigSync.save_configuration( filename = "/config/bigip.conf", save_flag = "SAVE_HIGH_LEVEL_CONFIG"  )


    except:
        print "Save Config Error. Check log."
        traceback.print_exc(file=sys.stdout)

def save_base_config_to_disk (obj):

    try:

        #Save Base Config
        obj.System.ConfigSync.save_configuration( filename = "/config/bigip_base.conf", save_flag = "SAVE_BASE_LEVEL_CONFIG"  )

    except:
        print "Save Config Error. Check log."
        traceback.print_exc(file=sys.stdout)


def save_high_config_to_disk (obj):

    try:

        #Save High Config
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

def reset_device_trust (obj, hostname ):

    try:
	obj.Management.Trust.reset_all(
					device_object_name = hostname,
					keep_current_authority = 'true',
					authority_cert = '',
					authority_key = '',
				      )

    except:
        print "Resetting Device Trust error. Check log."
        traceback.print_exc(file=sys.stdout)

def retrieve_interface ( obj, vlan, self_ips ):
    
    try:
	vlans = self_ips["vlan"]
	addresses = self_ips["address"]
	traffic_groups = self_ips["traffic_group"]
	interfaces = []
        for i in range(len(vlans)):
	    rx = r'{0}$'.format(vlan)
	    if re.search( rx , vlans[i], re.IGNORECASE ):
		#print "match: " + rx + " matches " + vlans[i]
		if traffic_groups[i] == "/Common/traffic-group-local-only":
		    #print "this self_ip is on traffic-group-local-only. Appending it to interfaces"
		    interfaces = addresses[i]    

	return interfaces

    except:
        print "Retrieving Interface error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_device_interface( obj, hostname, cs_ints, fo_ints, mir_ints  ):
    try:

	obj.Management.Device.set_configsync_address( devices = [hostname], addresses = [cs_ints] )



	unicast_objs = []
	for i in range(len(fo_ints)):
	    print "failover int = " +  fo_ints[i]
	    unicast_obj = {
			    'source' 	: { 'address' : fo_ints[i], 'port' : 1026 },
			    'effective' : { 'address' : fo_ints[i], 'port' : 1026 }
			  }
	    unicast_objs.append(unicast_obj)
     
    	obj.Management.Device.set_unicast_addresses(
						    devices = 	[hostname],
						    addresses = [unicast_objs]
						    )
	
	obj.Management.Device.set_primary_mirror_address( 
							    devices = [hostname],
							    addresses = [mir_ints[0]]
							)
	obj.Management.Device.set_secondary_mirror_address( 
							    devices = [hostname],
							    addresses = [mir_ints[1]]
							)
    
    except:
	print "set_device_interface error. Check log."
	traceback.print_exc(file=sys.stdout)

def add_authority_device (obj, node, username, password, hostname ):

    try:
	print "Adding Device routine: Address = " + node + " , Object_name is " + hostname  
	obj.Management.Trust.add_authority_device(
					address = node,
					username = username,
					password = password,
					device_object_name = hostname,
					browser_cert_serial_number = '',
					browser_cert_signature = '',
					browser_cert_sha1_fingerprint = '',
					browser_cert_md5_fingerprint = '',
				      )

    except:
        print "Resetting Device Trust error. Check log."
        traceback.print_exc(file=sys.stdout)

    

def check_sync_status ( obj, device_group ):
    try:
	# Note: This call was introduced in v11.4.0
	# sample output from get_sync_status
	# [{ 	'color': 'COLOR_GREEN', 
	#	'status': 'In Sync', 
	#	'member_state': 'MEMBER_STATE_IN_SYNC', 
	# 	'details': [], 'summary': 'All devices in the device group are in sync'}]

	statuses = []
	sync_status_seq = obj.Management.DeviceGroup.get_sync_status( device_groups = device_group )
	for i in range(len(sync_status_seq)):
	    dg_obj = sync_status_seq[i]
	    sync_status = dg_obj["status"]
	    statuses.append(sync_status)
	    #print "Device Sync Status is : " + sync_status 
	return statuses

    except:
        print "Error in checking Device Group Sync Status. Check log."
        traceback.print_exc(file=sys.stdout)


def wait_sync_status ( obj, device_group_name, sync_status_poll_interval, sync_status_timeout ):


    try:

	print "\n\nChecking Sync Status for device group " + device_group_name
	sync_status = ""
	for i in range(sync_status_timeout):
	    #takes an arrary
	    sync_status_a = check_sync_status( obj, [device_group_name] )
	    sync_status = sync_status_a[0]
	    if  sync_status == "In Sync":
		print "Sync Status is \"" + sync_status + "\"" 
		break
	    else:
		print "Sync Status is \"" + sync_status + "\". Waiting for : " + str(sync_status_poll_interval) + " secs." 
		time.sleep(sync_status_poll_interval)
    except:
        print "Error in Waiting for Sync Status. Check log."
        traceback.print_exc(file=sys.stdout)




def create_sync_failover_group( obj, name, cluster_device_names ):
    
    try:
	print cluster_device_names
	obj.Management.DeviceGroup.create( 	device_groups = [name], 
							types = ["DGT_FAILOVER"]
					 )

	obj.Management.DeviceGroup.add_device( 	device_groups = [name],
						      devices = [cluster_device_names]
					     ) 

	obj.Management.DeviceGroup.set_autosync_enabled_state (
								device_groups = [name],
								states = ["STATE_DISABLED"]
							      )

    except:

        print "Error in creating Failover Device Group Status. Check log."
        traceback.print_exc(file=sys.stdout)

def set_auto_sync_enabled (obj, name ):

    try:

        obj.Management.DeviceGroup.set_autosync_enabled_state (
                                                                device_groups = [name],
                                                                states = ["STATE_ENABLED"]
                                                              )

    except:

        print "Error in creating Device Group to Auto-Sync-Enabled. Check log."
        traceback.print_exc(file=sys.stdout)


def create_sync_only_group( obj, name, cluster_device_names ):
    
    try:

	obj.Management.DeviceGroup.create( 	device_groups = [name], 
							types = ["DGT_SYNC_ONLY"]
					 )
	obj.Management.DeviceGroup.add_device( 	device_groups = [name],
						      devices = [cluster_device_names]
					     ) 
	obj.Management.DeviceGroup.set_autosync_enabled_state (
								device_groups = [name],
								states = ["STATE_ENABLED"]
							      )

    except:

        print "Error in creating Sync-Only Device Group Status. Check log."
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


def create_folder( obj, folder_name, device_group, traffic_group ):

    
    try:

	obj.Management.Folder.create( folders = [folder_name] )
	obj.Management.Folder.set_device_group ( 
						    folders = [folder_name],
						    groups = [device_group]
						)
	obj.Management.Folder.set_traffic_group ( 
						    folders = [folder_name],
						    groups = [traffic_group]
						)

    except:

        print "Error in Creating Folder Status. Check log."
        traceback.print_exc(file=sys.stdout)

def create_traffic_group( obj, traffic_group_name ):

    
    try:

	obj.Management.TrafficGroup.create( traffic_groups = [traffic_group_name] )

    except:

        print "Error in Creating Traffic Group Status. Check log."
        traceback.print_exc(file=sys.stdout)


def set_ha_order( obj, traffic_group_name, device_order ):
    try: 
	
	# sample output from get_ha_order
	# [[
	#	{'device': '/Common/bigip-1.example.com', 'order': 0}, 
	#	{'device': '/Common/bigip-2.example.com', 'order': 1}, 
	#	{'device': '/Common/bigip-3.example.com', 'order': 2}
	#  ]]


	#print "traffic_group_name is " + traffic_group_name
	#print "device_order is " + str(device_order)
	obj.Management.TrafficGroup.add_ha_order( traffic_groups = [traffic_group_name],
					    orders = [device_order])
    
    except:

        print "Error in setting HA Order Status. Check log."


def set_auto_failback (obj, traffic_group ):

    try: 

	obj.Management.TrafficGroup.set_auto_failback_enabled_state( 
								    traffic_groups = [ traffic_group ],
								    states = ["STATE_ENABLED"]
								   )
    except:

        print "Error in setting Traffic Group Enabled State. Check log."

def set_mac_masquerade (obj, traffic_group, mac_address ):

    try: 

	obj.Management.TrafficGroup.set_mac_masquerade_address( 
								    traffic_groups = [ traffic_group ],
								    addresses = [ mac_address ]
								   )
    except:

        print "Error in setting Traffic Group Mac Masquerade Address. Check log."


def set_standby (obj, traffic_group, device ):

    try: 

	obj.System.Failover.set_standby_traffic_group_to_device( traffic_groups = [ traffic_group ], device = device )
	#obj.System.Failover.set_standby_traffic_group( traffic_groups = [ traffic_group ] )

    except:

        print "Error in setting Traffic Group Enabled State. Check log."


def set_device_offline (obj):

    try: 

	obj.System.Failover.set_offline()

    except:

        print "Error in setting Device State to OFFLINE. Check log."


def set_device_online (obj):

    try: 

	obj.System.Failover.set_offline_release()

    except:

        print "Error in setting Device State to ONLINE. Check log."






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
from suds.client import Client
from optparse import OptionParser
from configobj import ConfigObj
import bigsuds
  
# from suds import WebFault
# import logging
# logging.getLogger('suds.client').setLevel(logging.DEBUG)
# logging.getLogger('suds.metrics').setLevel(logging.DEBUG)
# logging.getLogger('suds').setLevel(logging.DEBUG)


##########################    START MAIN LOGIC   #########################

def main():

    parser = OptionParser()
    parser.add_option("-u", "--username", action="store", type="string", dest="username")
    parser.add_option("-b", "--bigips", action="store", type="string", dest="bigips")
    parser.add_option("-c", "--config_sync_vlan", action="store", type="string", dest="config_sync_vlan", default = "HA")
    parser.add_option("-f", "--failover_vlan", action="store", type="string", dest="failover_vlan", default="HA")
    parser.add_option("-m", "--mirror_vlan", action="store", type="string", dest="mirror_vlan", default="HA")
    (options, args) = parser.parse_args()


    if len(sys.argv) < 2:
	print "Usage %s:" % sys.argv[0]
	sys.exit()

    a = sys.argv[1:]

    #SET SOME GLOBALS
    #Timouts
    sync_status_poll_interval = 3
    sync_status_timeout = 15
    #username = options.username
    username = "admin"
    userpass = "admin"
    #Ideally want this
    #print "\nHello %s, please enter your password below.\n" % options.username
    #userpass = getpass.getpass()


############### START PROCESSING LOGIC  ##################

    #bigips have to be IPs (vs hostnames) as add Peer Device only accepts IPs 
    cluster = options.bigips.split(",")
    
    cluster_device_names = [] 
    failover_group_name = "my_sync_failover_group" 
    sync_only_group_name = "my_sync_only_group"
 
    for node in cluster:
	print "\n\nConnecting to Node: " + node
	#Now Initalize the bigsuds connection object
	try:   
	    b = bigsuds.BIGIP(
		hostname = node, 
		username = username, 
		password = userpass,
		)
	except Exception, e:
	    print e


	#START CONFIGURING 
	#print "\n\nSetting Hostname to " + hostname
	#set_hostname( b, hostname )
	print "\n\nGetting Hostname"
	hostname = get_hostname( b )
	print hostname
	cluster_device_names.append(hostname)
     
	print "\n\nResetting Device Trust with hostname to " + hostname
	reset_device_trust ( b, hostname )
	print "\nSleeping 5 seconds as this takes a little time..."	
	time.sleep(5)

	# could predermine which self_ips for each device you want to use 
	# but we'll try to reduce some of work involved with a little helper function 
	# and by making some assumptions
	# we will just have to submit the vlans and we'll look for unique self ip
	# associated with the vlans on all the devices 
	
	print "\nGetting Self IPs:" 
	self_ips = get_self_ips( b )

	cs_vlan = options.config_sync_vlan.split(",")
	fo_vlans = options.failover_vlan.split(",")
	mir_vlans = options.mirror_vlan.split(",")
	cs_ints = []
	fo_ints = []
	mir_ints = []
	for vlan in cs_vlan:
	   cs_ints.append(retrieve_interface(b, vlan, self_ips ))
	   #print "cs_ints are " + str(cs_ints)
	for vlan in fo_vlans:
	   fo_ints.append(retrieve_interface(b, vlan, self_ips ))
	   #print "fo_ints are " + str(fo_ints)
	for vlan in mir_vlans:
	   mir_ints.append(retrieve_interface(b, vlan, self_ips ))
	   #print "mir_ints are " + str(mir_ints)
	    

	print "\n\nSetting the Device Interfaces for "  + node
	set_device_interface( b, hostname, cs_ints, fo_ints, mir_ints  )      


 
    ### NOW GO TO SEED DEVICE AND CREATE CLUSTER	
    #Can make which device is the seed an option. 
    #For now will be first in the list
    seed = cluster[0]

     #Create list of peer devices depending on who is the seed
    nodes_to_add = []
    for node in cluster:
	if node != seed:
 	    nodes_to_add.append(node)

    # Set peers to Offline before adding them to a cluster
    # according to BZID 475503 Adding member to FODG triggers failover
    for node in nodes_to_add:
	print "\n\nConnecting to Node: " + node
	#Now Initalize the bigsuds connection object
	try:   
	    b = bigsuds.BIGIP(
		hostname = node, 
		username = username, 
		password = userpass,
		)
	except Exception, e:
	    print e

	print "\n\nSetting Node " + node + " to OFFLINE"
	set_device_offline(b) 


    print "\n\nNow Connecting to Cluster SEED node: " + seed

    #Initalize the bigsuds connection object
    try:   
	b = bigsuds.BIGIP(
	    hostname = seed, 
	    username = username, 
	    password = userpass,
	    )
    except Exception, e:
	print e



    for i in range(len(nodes_to_add)):
	print "\n\nAdding node " + nodes_to_add[i] + " to the trust as " + cluster_device_names[i+1]
	add_authority_device(b, nodes_to_add[i], username, userpass, cluster_device_names[i+1] )

	#Check sync
	wait_sync_status ( b, "device_trust_group", sync_status_poll_interval, sync_status_timeout )
# 	print "\n\nChecking Sync Status for device group " + device_group_name
# 	for i in range(sync_status_timeout):
# 	    #takes an array
# 	    sync_status = check_sync_status( b, [device_group_name] )
# 	    print "Sync Status is " + str(sync_status)
# 	    if [ sync_status == "In Sync"]:
# 		print "Sync Status is " + str(sync_status) 
# 		break
# 	    else:
# 		print "Sleeping for 1 sec...."
# 		time.sleep(sync_status_poll_interval)
#    

    #Give Suds client time to recover 
    time.sleep(5)

    print "\n\nSaving Config to Disk..."
    save_config_to_disk( b )

    #print "\n\nCreating Sync Only Group " + failover_group_name + " with " + str(cluster_device_names) + "."
    #create_sync_only_group( b, sync_only_group_name, cluster_device_names )
    #time.sleep(5)
    #print "\nSyncing Group"
    #sync_group(b, sync_only_group_name, cluster_device_names[0], "force" ) 
    #wait_sync_status ( b, sync_only_group_name, sync_status_poll_interval, sync_status_timeout )

    print "\n\nCreating Sync-Failover Group " + failover_group_name + " with " + str(cluster_device_names) + "."
    create_sync_failover_group( b, failover_group_name, cluster_device_names )
    time.sleep(5)

    print "\n\nSaving Config to Disk..."
    save_config_to_disk( b )

    print "\nSyncing Failover Group"
    sync_group(b, failover_group_name, cluster_device_names[0], "force" ) 
    wait_sync_status ( b, failover_group_name, sync_status_poll_interval, sync_status_timeout )

    print "\nSyncing default trust group"
    sync_group(b, "device_trust_group", cluster_device_names[0], "force" )
    wait_sync_status ( b, "device_trust_group", sync_status_poll_interval, sync_status_timeout )

    #print "\n\nCreating Traffic Groups\n"
    #Traffic Group 1 is created by default
    #create_traffic_group(obj, "traffic-group-1" )
    create_traffic_group(b, "traffic-group-2" )
    create_traffic_group(b, "traffic-group-3" )

#     #Create a bunch. Starts at 2 as 1 exists by default
#     for i in range(2,14):
# 	tg_name = "traffic-group-" + str(i)
# 	print "Creating Traffic Group: " + tg_name
# 	create_traffic_group(b, tg_name)
# 	#Sleep a little to get better LB of traffic groups
# 	time.sleep(3)
# 	    
#     Will just use Default "Load Aware" creation for now. However, can use something like HA Order
# 
    print "\n\nSetting HA Order"
    set_ha_order(b, "traffic-group-1", [
				          { 'device' : cluster_device_names[0], 'order' : 0 },
				          { 'device' : cluster_device_names[1], 'order' : 1 },
					  { 'device' : cluster_device_names[2], 'order' : 2 }

					]
		)
    set_ha_order(b, "traffic-group-2", [ 
					  { 'device' : cluster_device_names[1], 'order' : 0 },
					  { 'device' : cluster_device_names[2], 'order' : 1 },
					  { 'device' : cluster_device_names[0], 'order' : 2 }
				       ]
		)
    set_ha_order(b, "traffic-group-3", [ 
					  { 'device' : cluster_device_names[2], 'order' : 0 },
					  { 'device' : cluster_device_names[0], 'order' : 1 },
					  { 'device' : cluster_device_names[1], 'order' : 2 }
				       ]
		)

    set_auto_failback ( b, "traffic-group-1" ) 
    set_auto_failback ( b, "traffic-group-2" ) 
    set_auto_failback ( b, "traffic-group-3" )     

    set_mac_masquerade( b, "traffic-group-1", "02:01:d7:93:35:01")     
    set_mac_masquerade( b, "traffic-group-2", "02:01:d7:93:35:02")     
    set_mac_masquerade( b, "traffic-group-3", "02:01:d7:93:35:03")     

    print "\n\nSaving Config to Disk..."
    save_config_to_disk( b )

    set_auto_sync_enabled( b, failover_group_name ) 

    sync_group(b, "device_trust_group", cluster_device_names[0], "force" )
    wait_sync_status ( b, "device_trust_group", sync_status_poll_interval, sync_status_timeout )
    time.sleep(5);
#    sync_group(b, sync_only_group_name, cluster_device_names[0], "force" ) 
#    time.sleep(5);
    sync_group(b, failover_group_name, cluster_device_names[0], "force" ) 
    wait_sync_status ( b, failover_group_name, sync_status_poll_interval, sync_status_timeout )
    time.sleep(5);



    print "Setting Nodes back to ONLINE\n"

    for node in nodes_to_add:
	print "\n\nSetting Node " + node + " to ONLINE"
	#Now Initalize the bigsuds connection object
	try:   
	    b = bigsuds.BIGIP(
		hostname = node, 
		username = username, 
		password = userpass,
		)
	except Exception, e:
	    print e

	set_device_online(b) 

 
    print "\n\nNow Connecting to Cluster SEED node: " + seed

    #Initalize the bigsuds connection object to SEED node
    try:   
	b = bigsuds.BIGIP(
	    hostname = seed, 
	    username = username, 
	    password = userpass,
	    )
    except Exception, e:
	print e

    sync_group(b, "device_trust_group", cluster_device_names[0], "force" )
    wait_sync_status ( b, "device_trust_group", sync_status_poll_interval, sync_status_timeout )
    sync_group(b, failover_group_name, cluster_device_names[0], "force" ) 
    wait_sync_status ( b, failover_group_name, sync_status_poll_interval, sync_status_timeout )

    print "Setting Additional Traffic Groups to Standby"
#    set_standby( b, "traffic-group-1", "bigip1.example.com" )
#    set_standby( b, "traffic-group-2", "bigip2.example.com" )
#    set_standby( b, "traffic-group-3", "bigip3.example.com" )


#     # Need to go iterate across device nodes if want to create a User Level Partition.
    
#     for node in cluster:
# 	print "\n\nConnecting to Node: " + node
# 	#Now Initalize the bigsuds connection object
# 	try:   
# 	    b = bigsuds.BIGIP(
# 		hostname = node, 
# 		username = username, 
# 		password = userpass,
# 		)
# 	except Exception, e:
# 	    print e
# 
 
	#NOTE: Can't set inheritence on the folder?
        #print "\n\nCreating Folder \"Spanned-VIP\" with Device Group " + sync_only_group_name
	#create_folder( b, "/Spanned-VIP", sync_only_group_name, "traffic-group-1" )

#Unique to Tony
    
    #One last sync for good measure
#    sync_group(b, "device_trust_group", cluster_device_names[0], "force" )
#   time.sleep(5);
#    sync_group(b, sync_only_group_name, cluster_device_names[0], "force" ) 
#   time.sleep(5);
#    sync_group(b, failover_group_name, cluster_device_names[0], "force" ) 
#    time.sleep(5);


if __name__ == "__main__":
    main()
