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

    """ fields param = dict of field names 
    
    :param my_class: class to name to use.
    :type my_class: string.
    :param container: container name to use.
    :type container: string.
    :param container_class: container class name to use.
    :type container_class: string.
    :param fields: field values to use.
    :type fields: array of strings.
    :returns: 
    :raises:

    """
    try:
	class_instance_key = { 'name' : my_class , 
			       'class_name' : my_class 
# 			       'container' : container, 
#			       'container_class' : "None" 
			     } 

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

#   Possible Values for LT Class on v11.5.1
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






def get_license_from_F5_License_Server ( server_hostname, dossier_string, eula_string, email, 
                                         firstName, lastName, companyName, phone, jobTitle, 
                                        address, city, stateProvince, postalCode, country ):

    try:

        license_string = ""
        # Unfortunately, F5 wsdl on license server references http but F5 only accepts https so as an ugly workaround need to    
        # download wsdl, save to disk, replace links http with https, and have SUDS client reference local file instead 
        #(eg. url = "file:///home/admin/f5wsdl.xml")

        download_url = "https://" + server_hostname + "/license/services/urn:com.f5.license.v5b.ActivationService?wsdl"

        # Check to see if there's a copy of wsdl file on disk first
        # Careful with this behavior if you switch server hostnames.  
        local_wsdl_file_name = server_hostname + 'f5wsdl-w-https.xml'
        wsdl_data = []

        try: 
            with open(local_wsdl_file_name, 'r') as fh_wsdl:
                wsdl_data = fh_wsdl.read()
        except:
            print "Can't find a locally stored WSDL file."


        if not wsdl_data:
            print "Attempting to fetch wsdl online."
            f5wsdl = urllib2.urlopen(download_url) 
            newlines = []
            for line in f5wsdl:
                # do the replacing here
                newlines.append(line.replace('http://' + server_hostname , 'https://' + server_hostname))

            fh_local = open(local_wsdl_file_name,'w')
            fh_local.writelines(newlines) 
            fh_local.close()

        # put url going to pass to client in file format
        url = "file:" + urllib.pathname2url(os.getcwd()) + "/" +  local_wsdl_file_name

        #Now create client object using wsdl from disk instead of the interwebs.
        client = Client(url)

        # NOT using below as will just try actually licensing and fail then if needed
        # try:
        #    # ping() method should return string containing date
        #    print "Checking License Service Reachability..."
        #    return_ping_date = client.service.ping()
        # except:
        #    print "License SOAP service unreachable. Check network connectivity."
        #    return
        

        transaction = client.factory.create('ns0:LicenseTransaction')
        # If eula isn't present on first call to getLicense, transaction will fail
        # but it will return a eula after first attempt 
        transaction = client.service.getLicense(    
                                                dossier = dossier_string,
                                                eula = eula_string, 
                                                email = email, 
                                                firstName = firstName , 
                                                lastName = lastName, 
                                                companyName = companyName, 
                                                phone = phone, 
                                                jobTitle = jobTitle, 
                                                address = address, 
                                                city = city, 
                                                stateProvince = stateProvince, 
                                                postalCode = postalCode, 
                                                country = country,
                                                )
        
        #Extract the eula offered from first try
        eula_string = transaction.eula

        if transaction.state == "EULA_REQUIRED":
            #Try again, this time with eula populated
            transaction = client.service.getLicense(    
                                                        dossier = dossier_string,
                                                        eula = eula_string, 
                                                        email = email, 
                                                        firstName = firstName , 
                                                        lastName = lastName, 
                                                        companyName = companyName, 
                                                        phone = phone, 
                                                        jobTitle = jobTitle, 
                                                        address = address, 
                                                        city = city, 
                                                        stateProvince = stateProvince, 
                                                        postalCode = postalCode, 
                                                        country = country,
                                                        )
        
        if transaction.state == "LICENSE_RETURNED":
            license_string = transaction.license
        else: 
            print "Can't retrieve license from Licensing server"
            print "License server returned error: Number:" + str(transaction.fault.faultNumber) + " Text: " + str(transaction.fault.faultText)

        return license_string

    except:
        print "Can't retrieve License from Server"
        traceback.print_exc(file=sys.stdout)



def get_reg_keys(obj):

    try:

        reg_keys = [ ]
        reg_keys = obj.Management.LicenseAdministration.get_registration_keys()
        return reg_keys

    except:
        print "Get Reg Keys error. Check log."
        traceback.print_exc(file=sys.stdout)



def get_dossier (obj, reg_keys ):

    try:

        dossier_string = obj.Management.LicenseAdministration.get_system_dossier ( reg_keys )
        return dossier_string

    except:
        print "Get Dossier error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_eula_file (obj):

    try:
        
        eula_char_array = obj.Management.LicenseAdministration.get_eula_file( )
        eula_string =  base64.b64decode(eula_char_array)
        return eula_string

    except:
        print "Get eula_file. Check log."
        traceback.print_exc(file=sys.stdout)


def install_license (obj, license_string ):

    try:

        license_char_array = base64.b64encode(license_string)
        obj.Management.LicenseAdministration.install_license ( license_file_data = license_char_array )

    except:
        print "Install License error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_license_status (obj):

    try:

        license_status = obj.Management.LicenseAdministration.get_license_activation_status()
        return license_status

    except:
        print "Get License Status error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_provision (obj, modules ):
    try:
        modules_seq = []
	provision_level_seq = []
        print "%-30s" % "key:" + "%s" % "value:"
        print "%-30s" % "----" + "%s" % "------"
	for i in range(len(modules)):
	    module = modules[i]
	    for k,v in module.items():
                print "%-30s" % k + "%s" % v
		module_obj = { 'name' : k, 'value' : v }
		modules_seq.append( module_obj )
	    
		
		if k == "ltm":
		    module_seq = [ "TMOS_MODULE_LTM" ]
		if k == "gtm":
		    module_seq = [ "TMOS_MODULE_GTM" ]
		if k == "avr":
		    module_seq = [ "TMOS_MODULE_AVR" ]
		#....


		if v == "none":
		    provision_level_seq = [ "PROVISION_LEVEL_NONE" ]
		if v == "minimum":
		    provision_level_seq = [ "PROVISION_LEVEL_MINIMUM" ]
		if v == "nominal":
		    provision_level_seq = [ "PROVISION_LEVEL_NOMINAL" ]
		if v == "dedicated":
		    provision_level_seq = [ "PROVISION_LEVEL_DEDICATED" ]
		if v == "custom":
		    provision_level_seq = [ "PROVISION_LEVEL_CUSTOM" ]
		if v == "unknown":
		    provision_level_seq = [ "PROVISION_LEVEL_UNKNOWN" ]


        obj.Management.Provision.set_level( module_seq, provision_level_seq )


    except:
        print "Set Provision error. Check log."
        traceback.print_exc(file=sys.stdout)




def get_provision (obj, modules):

    try:

        module_list = obj.Management.Provision.get_provisioned_list()

        level_list = obj.Management.Provision.get_level( modules = module_list )
        print "%-30s" % "Module:" + "%s" % "Level:"
        print "%-30s" % "----" + "%s" % "------"
        for i in range(len(module_list)):
            print "%-30s" % module_list[i] + "%s" % level_list[i]


    except:
        print "Get Provision error. Check log."
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

def key_import_from_PEM( obj, cert_mode, key_id, my_key_pem ):

    try:


        mode = cert_mode
        key_ids = [ key_id ]
        pem_data = [ my_key_pem ]
        overwrite = bool(1)

        keys_output = obj.Management.KeyCertificate.key_import_from_pem( 
                                                                                mode, 
                                                                                key_ids,
                                                                                pem_data,
                                                                                overwrite
                                                                              )
        return keys_output

    except:
        print "Certificate Import from PEM Error. Check log."
        traceback.print_exc(file=sys.stdout)               


def install_management_cert( obj, p12_password, file_location_on_bigip ):
    try:

        mode = "MANAGEMENT_MODE_WEBSERVER"
        ids =  ["server"]
        file_names = [ file_location_on_bigip ]
        passwords = [ p12_password ]
        overwrite = bool(1)

        upload_output = obj.Management.KeyCertificate.pkcs12_import_from_file(
                                                                                mode,
                                                                                ids,
                                                                                file_names,
                                                                                passwords,
                                                                                overwrite
                                                                              )
    except:
        print "Certificate Import from PKCS12 Error. Check log."
        traceback.print_exc(file=sys.stdout)



def modify_db_keys ( obj, db_keys ):

    try:

        variables = []

        print "%-45s" % "key:" + "%s" % "value:"
        print "%-45s" % "----" + "%s" % "------"
	for i in range(len(db_keys)):
	    db_key = db_keys[i]
	    for k,v in db_key.items():
                print "%-45s" % k + "%s" % v
		db_key_obj = { 'name' : k, 'value' : v }
		variables.append( db_key_obj )
	    
        obj.Management.DBVariable.modify( variables )

    except:
        print "DB Key Change Error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_db_keys ( obj, variables ):
    try:

        query_output = obj.Management.DBVariable.query( variables )

        print "%-45s" % "key:" + "%s" % "value:"
        print "%-45s" % "----" + "%s" % "------"
        for i in range(len(query_output)):
                db_key = query_output[i]
                print "%-45s" % db_key['name'] + "%s" % db_key['value']
               
    except:
        print "DB Key Read Error. Check log."
        traceback.print_exc(file=sys.stdout)


def upload_software (obj ):

    try:

        print "To Do"

    except:
        print "Upload Software error. Check log."
        traceback.print_exc(file=sys.stdout)

def install_software (obj ):

    try:

        print "To Do"

    except:
        print "Install Software error. Check log."
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


def install_certificate (obj, hostname ):

    try:

        print "test"

    except:
        print "Install Certificate error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_mcpd_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'daemon_mcpd', 'None', 'None', fields )

    except:
        print "Set MCPD Config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_mcpd_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'daemon_mcpd', 'None', 'None', fields )

    except:
        print "get MCPD Config error. Check log."
        traceback.print_exc(file=sys.stdout)



def set_cli_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'cli', 'None', 'None', fields )

    except:
        print "Set CLI Config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_cli_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'cli', 'None', 'None', fields )

    except:
        print "get CLI Config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_system_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'system','None', 'None',  fields )

    except:
        print "Set SYSTEM Config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_system_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'system', 'None', 'None', fields )

    except:
        print "get SYSTEM Config error. Check log."
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




def set_ntp_servers (obj, ntp_addresses ):

    try:
        obj.System.Inet.set_ntp_server_address( ntp_addresses = ntp_addresses )

    except:
        print "Set NTP servers error. Check log."
        traceback.print_exc(file=sys.stdout)



def set_ntp_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'ntp', 'None', 'None', fields )

    except:
        print "Set NTP Config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_ntp_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'ntp', 'None', 'None', fields )

    except:
        print "get NTP Config error. Check log."
        traceback.print_exc(file=sys.stdout)



def set_dns_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'dns', 'None', 'None', fields )

    except:
        print "Set DNS Config error. Check log."
        traceback.print_exc(file=sys.stdout)
 
def get_dns_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'dns', 'None', 'None', fields )

    except:
        print "Get DNS Config error. Check log."
        traceback.print_exc(file=sys.stdout)
        

def set_sshd_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'sshd', 'None', 'None', fields )

    except:
        print "Set SSHD config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_sshd_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'sshd','None', 'None',  fields )

    except:
        print "Get SSHD Config error. Check log."
        traceback.print_exc(file=sys.stdout)
 

def set_syslog_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'syslog', 'None', 'None', fields )

    except:
        print "Set SYSLOG config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_syslog_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'syslog', 'None', 'None', fields )

    except:
        print "Get SYSLOG config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_httpd_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'httpd', 'None', 'None', fields )

    except:
        print "Set HTTPD config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_httpd_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'httpd', 'None', 'None', fields )

    except:
        print "Get HTTPD config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_snmp_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'snmpd', 'None', 'None', fields )

    except:
        print "Set SNMPD config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_snmp_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'snmpd', 'None', 'None', fields )

    except:
        print "get SNMPD config error. Check log."
        traceback.print_exc(file=sys.stdout)



def set_snmp_trapsink_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'trapsink', 'None', 'None', fields )

    except:
        print "Set SNMPD trapsink trapsink config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_snmp_trapsink_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'trapsink', 'None', 'None', fields )

    except:
        print "get SNMPD trapsink trapsink config error. Check log."
        traceback.print_exc(file=sys.stdout)



def set_snmp_trap2sink_config ( obj, fields ):

    try:
        set_LTConfig_field_values ( obj, 'trap2sink', 'None', 'None', fields )

    except:
        print "Set SNMPD trap2sink config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_snmp_trap2sink_config ( obj, fields ):

    try:
        get_LTConfig_field_values ( obj, 'trap2sink', 'None', 'None', fields )

    except:
        print "get SNMPD trap2sink config error. Check log."
        traceback.print_exc(file=sys.stdout)



def set_snmp_trapsess_config ( obj, trap_sinks, fields_arrays, values_arrays ):

    try:
	# This is a dossie !
        class_instance_key_list = []

        for trap_sink in trap_sinks:
            #BIGIP Default Naming Convention
            class_name_field = "i" + trap_sink.replace(".", "_") + "_1"
            snmp_trapsess_class = create_class(obj, "trapsess", class_name_field, "snmpd", "None" )
            class_instance_key_list.append(snmp_trapsess_class)
            
        set_field_values_from_custom_class_list ( b, class_instance_key_list, fields_arrays, values_arrays) 

    except:
        print "Set SNMPD trapsess config error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_snmp_trapsess_config ( obj, fields ):

    try:

	# This is a dossie !

        class_instance_key_seq_seq = obj.LTConfig.Class.get_list_of_instances(class_names=['trapsess'])
        class_instance_key_seq = class_instance_key_seq_seq[0] 

        field_instance_names_seq_seq = obj.LTConfig.Field.typefactory.create('Common.StringSequenceSequence')
        field_instance_names_seq_seq.item = []

        for c in range(len(class_instance_key_seq)):
            
            field_instance_names_seq = obj.LTConfig.Field.typefactory.create('Common.StringSequence')
            field_instance_names_seq.item = fields
            field_instance_names_seq_seq.item.append(field_instance_names_seq)

        values_output = obj.LTConfig.Field.get_values( 
                    class_instance_keys = class_instance_key_seq , 
                    field_instance_names = field_instance_names_seq_seq, 
                    )
    
        print "%-30s" % "field" + "%s" % "value"
        print "%-30s" % "-----" + "%s" % "-----"
        for c in range(len(class_instance_key_seq)):
            print "Trapsess Instance Name = " + class_instance_key_seq[c].name + ":"
            for i in range(len(fields)):
                print "%-30s" % fields[i].strip() + "%s" % values_output[c][i].replace('\n','\n\t\t\t\t').strip()
        return values_output

    except:
        print "Get SNMPD trapsess config error. Check log."
        traceback.print_exc(file=sys.stdout)




#  Definitions using native Management.SNMPConfiguration methods use set_snmp_config_XXXX syntax
#  These are duplicate of LTConfig methods above but are presented as an example
 
def set_snmp_config_client_access (obj, networks, masks):

    try:
        #Note, this can be done with LTConfig as well (see above)

        client_access_seq = obj.Management.SNMPConfiguration.typefactory.create('Management.SNMPConfiguration.ClientAccessSequence')
        client_access_seq.item = []

        for i in range(len(networks)):
            client_access_obj = obj.Management.SNMPConfiguration.typefactory.create('Management.SNMPConfiguration.ClientAccess')
            client_access_obj.address = networks[i]
            client_access_obj.netmask = masks[i]
            client_access_seq.item.append(client_access_obj)

        obj.Management.SNMPConfiguration.set_client_access( client_access_info = client_access_info_seq )

    except:
        print "Set SNMP config error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_snmp_config_client_access (obj, networks, masks):

    try:
        
        networks_output = obj.Management.SNMPConfiguration.get_client_access()

        for network in networks_output:
            print "Network = " + network.address + "/" + network.netmask

        return networks_output

    except:
        print "Get Client Access config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_snmp_config_system_info (obj, sys_name, sys_location, sys_contact, sys_description, sys_object_id, sys_services ):

    try:
        #Note, this can be done with LTConfig as well (see above)

        system_info_obj = obj.Management.SNMPConfiguration.typefactory.create('Management.SNMPConfiguration.SystemInformation')
        system_info_obj.sys_name = sys_name
        system_info_obj.sys_location = sys_location
        system_info_obj.sys_contact = sys_contact
        system_info_obj.sys_description = sys_description
        system_info_obj.sys_object_id = sys_object_id
        system_info_obj.sys_services = sys_services

        obj.Management.SNMPConfiguration.set_system_information( system_info = system_info_obj )

    except:
        print "Set SNMP System Info error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_snmp_config_system_info (obj):

    try:
        #Note, this can be done with LTConfig as well (see above)

        system_info_output = obj.Management.SNMPConfiguration.get_system_information( )
        print "%-30s" % "field" + "%s" % "value"
        print "%-30s" % "-----" + "%s" % "-----"

        print "%-30s" % "sys_name" + "%s" % system_info_output.sys_name 
        print "%-30s" % "sys_location" + "%s" %system_info_output.sys_location 
        print "%-30s" % "sys_contact" + "%s" %system_info_output.sys_contact 
        print "%-30s" % "sys_description" + "%s" % system_info_output.sys_description 
        print "%-30s" % "sys_object_id" + "%s" % system_info_output.sys_object_id 
        print "%-30s" % "sys_services" + "%s" % str(system_info_output.sys_services) 

        return system_info_output


    except:
        print "Get SNMP System Info error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_snmp_config_trap2sinks (obj, sink_hosts, sink_ports, sink_communities ):

    try:
        #Note, this can be done with LTConfig as well (see above)

        sink_obj_type = obj.Management.SNMPConfiguration.typefactory.create('Management.SNMPConfiguration.SinkType')

        sink_info_obj_seq = obj.Management.SNMPConfiguration.typefactory.create('Management.SNMPConfiguration.SinkInformationSequence')
        sink_info_obj_seq.item = []

        for i in range(len(sink_hosts)):
            sink_info_obj = obj.Management.SNMPConfiguration.typefactory.create('Management.SNMPConfiguration.SinkInformation')
            sink_info_obj.sink_host = sink_hosts[i]
            sink_info_obj.sink_port = sink_ports[i]
            sink_info_obj.sink_community = sink_communities[i]
            sink_info_obj_seq.item.append(sink_info_obj)
        
        #print sink_info_obj_seq

        obj.Management.SNMPConfiguration.set_trap_sinks( sink_type = sink_obj_type.SINK_TRAP2SINK, sink_info = sink_info_obj_seq )
                            

    except:
        print "Set SNMP config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_radius_server (obj, server_name, ip_or_hostname, service, secret ):

    try:
        radius_server_obj = obj.Management.RADIUSServer.typefactory.create('Management.RADIUSServer.RADIUSServerDefinition')
        radius_server_obj.name = server_name
        radius_server_obj.ip_or_hostname = ip_or_hostname
        radius_server_obj.service = service
        radius_server_obj.secret = secret

        radius_server_seq = obj.Management.RADIUSServer.typefactory.create('Management.RADIUSServer.RADIUSServerDefinitionSequence')
        radius_server_seq.item = [ radius_server_obj ]

        obj.Management.RADIUSServer.create( servers = radius_server_seq )


    except:
        print "Set RADIUS Server config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_radius_config (obj, config_name , server_names  ):

    #Method only creates one config name with multiple servers 

    try:

        config_name_seq = [ config_name ]

        radius_server_names_seq = obj.Management.RADIUSConfiguration.typefactory.create('Common.StringSequence')
        radius_server_names_seq.item = []
        radius_server_names_seq_seq = obj.Management.RADIUSConfiguration.typefactory.create('Common.StringSequenceSequence')
        radius_server_names_seq_seq.item = []

        for server in server_names:
                radius_server_names_seq.item.append(server)

        radius_server_names_seq_seq.item.append(radius_server_names_seq)


        obj.Management.RADIUSConfiguration.create( config_names = config_name_seq, servers = radius_server_names_seq_seq )

    except:
        print "Set RADIUS config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_tacacs_config (obj, config_name, secret, service_name, protocol_name, server_ips ):

    try:

        config_name_seq = [ config_name ]
        secrets_seq = [ secret ]
        service_names_seq = [ service_name ]
        protocol_names_seq = [ protocol_name ]

        tacacs_server_ips_seq = obj.Management.TACACSConfiguration.typefactory.create('Common.StringSequence')
        tacacs_server_ips_seq.item = []
        tacacs_server_ips_seq_seq = obj.Management.TACACSConfiguration.typefactory.create('Common.StringSequenceSequence')
        tacacs_server_ips_seq_seq.item = []

        for server in server_ips:
                tacacs_server_ips_seq.item.append(server)

        tacacs_server_ips_seq_seq.item.append(tacacs_server_ips_seq)


        obj.Management.TACACSConfiguration.create(  config_names = config_name_seq, 
                                                    secrets = secrets_seq, 
                                                    service_names = service_names_seq, 
                                                    protocol_names = protocol_names_seq, 
                                                    servers = tacacs_server_ips_seq_seq )

    except:
        print "Set TACACS+ config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_system_auth_default_role( obj, system_auth_role ):
    try:

        obj.Management.UserManagement.set_default_role( role = system_auth_role )

    except:
        print "Set SYSTEM AUTH Default Role config error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_system_auth_default_partition( obj, system_auth_partition ):
    try:

        obj.Management.UserManagement.set_default_partition( partition = system_auth_partition )

    except:
        print "Create SYSTEM AUTH Default Partition config error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_system_auth_console_access( obj, system_auth_console ):

    # Console is set to bpsh by default in 10.x 
    # And unfortunately, this method is only boolean and doesn't allow to set the shell
    # To set the shell, we'll use LTConfig 
    try:
        if system_auth_console == "True":
            console_access_bool = bool(1)
        else:
            console_access_bool = bool(0)
        
        obj.Management.UserManagement.set_remote_console_access( enabled = console_access_bool )

    except:
        print "Create SYSTEM AUTH Console Access config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_system_auth_default_shell( obj, system_auth_shell ):
    # Unfortunately, this method doesn't allow you to set shell for remote-user. 
    try:
        obj.Management.UserManagement.set_login_shell( user_names = [ "remote-user" ], shells = [ system_auth_shell ] )

    except:
        print "Create SYSTEM AUTH Default Shell config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_system_auth_remote_users_config( obj, fields ):
    #LTConfig version
    try:
        set_LTConfig_field_values ( obj, 'remote_users', 'None', 'None', fields )

    except:
        print "Set SNMPD config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_system_auth_ad_config ( obj, server, base_dn, bind_dn, bind_pass ):
    
    try:
	#Hard coding some things for now
	config_name = "system-auth"
	obj.Management.LDAPConfiguration.create_default_authentication_ad_configuration( search_base_dn = base_dn , servers = [server]  )
	
	obj.Management.LDAPConfiguration.set_bind_distinguished_name( config_names = [ config_name ],
								      bind_dns = [ bind_dn ]   )
	obj.Management.LDAPConfiguration.set_bind_password( config_names = [ config_name ],
								bind_passwords = [ bind_pass ]   )
	obj.Management.LDAPConfiguration.set_check_roles_group_state( config_names = [ config_name ],
								states = ["STATE_DISABLED"]   )
	obj.Management.UserManagement.set_authentication_method( auth_method = "AUTHENTICATION_METHOD_ACTIVE_DIRECTORY"  )

	#Until Configure Remote Role Groups 
        obj.Management.UserManagement.set_default_role( role = "USER_ROLE_ADMINISTRATOR" )
	
	#Have to use LTConfig for some of this 
	#no set_default_remote_console_access call
        
        # >>> b.LTConfig.Field.get_list(["remote_users"])
  	# [['default_partition', 'default_role', 'description', 'remote_console_access']]
 
	print "\n\nSetting Console to TMSH"
	set_LTConfig_field_values ( obj, 'remote_users', 'None', 'None', { 'remote_console_access' : "tmsh"} )	
	print "\nGetting Console Setttings"
	get_LTConfig_field_values ( obj, 'remote_users', 'None', 'None', { 'remote_console_access' : "tmsh"} )	

    except:
        print "Set AD Auth  config error. Check log."
        traceback.print_exc(file=sys.stdout)


def set_remote_roles( obj, roles ):

    try:
	# Takes dict that look like:
	# { "guests" : guest_dict, "network-ops" : network_ops_dict , "pmes" : pme_dict, "pm" : pm_dict }
	# where: 
	# role name = "guest"
     	# guest_dict = {   
	#		    'role' : "guest", 
	#		    'line_order' : 1002, 
	#		    'attribute' :  "memberOf=cn=network-guests,ou=LAB,dc=example,dc=com",
	#		    'user_partition' : "All", 
	#		    'console' : "tmsh",
	#		    'deny' : "false",
	#		    'description' : "none"
	#	       }	
 	# Note how LTConfig items differ from  
	# >>> b.LTConfig.Field.get_list(["remote_role"])
 	# [[]]
 	# >>> b.LTConfig.Field.get_list(["role_info"])
 	# [['attribute', 'console', 'deny', 'description', 'line_order', 'role', 'user_partition']]

	role_names_dict = roles
	class_instance_keys = []
	field_instance_names = []
	values = []
	for k,v in role_names_dict.items():
		class_instance_key = {'class_name': 'role_info', 'container': '/Common/remoterole', 'name': k, 'container_class': None}
		class_instance_keys.append(class_instance_key)
	        #Just use first one as a structure. Requires they're all the same
		field_names = []
		field_values = []
		for i,j in v.items():
		    field_names.append(i)
		    field_values.append(j)
		field_instance_names.append(field_names)
		values.append(field_values) 
	    
 	obj.LTConfig.Field.set_values(
                    create_instances_if_needed = 1,
                    class_instance_keys = class_instance_keys ,
                    field_instance_names = field_instance_names ,
                    values = values  )
	

    except:
        print "Set Remote Role config error. Check log."
        traceback.print_exc(file=sys.stdout)

def set_management_routes( obj, route_names , route_nets, route_masks, route_gws ):
    try:
	
	destinations = [ ]
	attributes = [ ]

        for i in range(len(route_nets)):
                route_dest_obj = {     'address' : route_nets[i], 
				       'netmask' : route_masks[i] }
                destinations.append(route_dest_obj)

                route_attribute_obj = { 'gateway' : route_gws[i] }
                attributes.append(route_attribute_obj)
   
        obj.Networking.RouteTableV2.create_management_route(
							routes = route_names, 
                                                        destinations = destinations, 
                                                        attributes = attributes
                                                       )

    except:
        print "Set Route config error. Check log."
        traceback.print_exc(file=sys.stdout)


def get_management_routes ( obj ):

    try:
        
	management_route_names = []
	management_route_nets = []
        management_route_masks = []
        management_route_gws = []

        management_route_names_output = obj.Networking.RouteTableV2.get_management_route_list() 
        management_route_destinations = obj.Networking.RouteTableV2.get_management_route_destination( routes = management_route_names_output ) 
        management_route_gateways = obj.Networking.RouteTableV2.get_management_route_gateway( routes = management_route_names_output )

        print "%-20s" % "Destination" + "%-20s" % "Genmask" + "%-20s" % "Gateway"
        print "%-20s" % "-----------" + "%-20s" % "-------" + "%-20s" % "-------"
        for i in range(len(management_route_destinations)):
	    route = management_route_destinations[i]
            management_route_nets.append( route['address'] )
            management_route_masks.append( route['netmask'] )
            management_route_gws.append(management_route_gateways[i])

            print   "%-20s" % route['address'] + \
                    "%-20s" % route['netmask'] + \
                    "%-20s" % management_route_gateways[i] 

        return ( management_route_nets, management_route_masks, management_route_gws )

    except:
        print "Get management Route config error. Check log."
        traceback.print_exc(file=sys.stdout)

 
                                                        
def set_trunk (obj, trunk_name, interfaces, lacp_enabled, lacp_timeout, lacp_active_state ):

    # Method currently only accepts one trunk at a time
    try:

        trunk_name_seq = [ trunk_name ]

        if lacp_enabled == "True":
            lacp_enabled_state = 1
        else:
            lacp_enabled_state = 0

        lacp_enabled_seq = [ lacp_enabled_state ]
    
        interfaces_seq_seq = [[interfaces]]

        obj.Networking.Trunk.create (
                                        trunks = trunk_name_seq,
                                        lacp_states = lacp_enabled_seq,
                                        interfaces = interfaces_seq_seq
                                    )

        timeout_options_seq = [ lacp_timeout ]

        obj.Networking.Trunk.set_lacp_timeout_option ( 
                                        trunks = trunk_name_seq,
                                        timeout_options = timeout_options_seq
                                                    )

        lacp_active_state_seq = [ lacp_active_state ]

        obj.Networking.Trunk.set_active_lacp_state ( 
                                        trunks = trunk_name_seq,
                                        states = lacp_active_state_seq
                                                    )
        

    except:
        print "Create Trunk config error. Check log."
        traceback.print_exc(file=sys.stdout)

def get_trunk (obj  ):

    try:
        trunk_name_seq = obj.Networking.Trunk.get_list()
        interfaces_seq = obj.Networking.Trunk.get_interface( trunk_name_seq )
        operational_member_seq = obj.Networking.Trunk.get_operational_member_count( trunk_name_seq )
        lacp_enabled_state_seq = obj.Networking.Trunk.get_lacp_enabled_state( trunk_name_seq )
        lacp_timeout_option_seq = obj.Networking.Trunk.get_lacp_timeout_option( trunk_name_seq )
        media_status_seq =  obj.Networking.Trunk.get_media_status( trunk_name_seq )
        
        for t in range(len(trunk_name_seq)):
            print ""
            print "%-25s" % "Trunk Name:"           + "%-25s" % trunk_name_seq[t] 
            print "%-25s" % "----------------"      + "%-25s" % "----------------"
            print "%-25s" % "LACP Enabled:"         + "%-25s" % lacp_enabled_state_seq[t]
            print "%-25s" % "LACP Timeout:"         + "%-25s" % lacp_timeout_option_seq[t]
            print "%-25s" % "Interfaces:"           + "%-25s" % interfaces_seq[t]
            print "%-25s" % "Operational Members:"  + "%-25s" % operational_member_seq[t]
            print "%-25s" % "Media Status:"         + "%-25s" % media_status_seq[t]  
        
    except:
        print "Create Trunk config error. Check log."
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
            # gateway_address_int = ip2int(gateway_networks[i]) + 1
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
		#print "j member is " + str(j)
		#print "pool_ports[i][j] is: " + str(pool_ports[i][j])
		ip_port_def = { 'address' : members[j] , 'port' : pool_ports[i][j] }
		ip_port_def_seq.append(ip_port_def)
		#print ip_port_def_seq
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
			'default_pool_name' : "pool_http"
			}
	    resources.append(resource)
	    virtual_profiles = []
	    if protocol_profiles[i]:
		profile = {
			    'profile_name' : "http",
			    'profile_context' : "PROFILE_CONTEXT_TYPE_ALL",
			  }
		virtual_profiles.append(profile)
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

        #file_chain_type = obj.System.ConfigSync.typefactory.create('Common.FileChainType')
        chain_type = "FILE_FIRST"
        #file_transfer_context = obj.System.ConfigSync.typefactory.create('System.ConfigSync.FileTransferContext')

        while poll:
            file_data = ""
            bytes_read = stream_io.read( preferred_chunk_size )

            if len(bytes_read) != preferred_chunk_size:
                if total_bytes == 0:
                    chain_type = "FILE_FIRST_AND_LAST"
                else:
                    chain_type = "FILE_LAST"
                poll = bool(0)
            
            total_bytes = total_bytes + len(bytes_read)
            file_transfer_context = { 'file_data' : base64.b64encode(bytes_read), 'chain_type' : chain_type }

            obj.System.ConfigSync.upload_file( file_name = dest_file_name, file_context = file_transfer_context )
            chain_type = "FILE_MIDDLE"
            #print "Total Uploaded Bytes = %s " % total_bytes 

        #print "Total Uploaded Bytes = %s " % total_bytes + " for filename %s" %  dest_file_name

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



# Couple of anonymous functions
# Note: Functions do not currently accept IPV6.
# Will need Socket v2.3 w/ socket.inet_pton & inet_ntop or another module like netaddr (v 0.7 or higher)
ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))


##########################    START MAIN LOGIC   #########################


if __name__ == "__main__":

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

    parser = OptionParser()
    parser.add_option("-c", "--config", action="store", type="string", dest="bigip_config_vars")
    parser.add_option("-u", "--username", action="store", type="string", dest="username")
    parser.add_option("-b", "--bigip", action="store", type="string", dest="bigip")
    parser.add_option("-s", "--license_server", action="store", type="string", dest="license_server_hostname", default="activate.f5.com" )
    parser.add_option("-r", "--reg_keys", action="store", type="string", dest="reg_keys_string" )
    parser.add_option("-l", "--license", action="store", type="string", dest="local_license_file_name")
    parser.add_option("-e", "--eula", action="store", type="string", dest="local_eula_file_name")
    (options, args) = parser.parse_args()


    ################### LOAD MOST OF CONFIG VARIABLES FROM FILE  ##############################
    # As BIGIP's configs are a little complex, really need to implement 
    # a more robust legitimate config parsing/importing mechanism 
    # ideally need to import from an actual database so can modify with webapp or even from original tmsh syntax  
    # for now, will use simple .ini style config and require the configobj module
    # http://www.voidspace.org.uk/python/configobj.html
    # which appears to be somewhat popular and preferred over builtin configparser module
    # https://wiki.python.org/moin/ConfigParserShootout
    ###########################################################################################

    print "bigip variables configuration file = " + options.bigip_config_vars + " !"
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
    #if we want to grab password from prompt instead
    #print "\nHello %s, please enter your password below.\n" % options.username
    #userpass = getpass.getpass()

    #Initalize the bigsuds connection object
    try:   
	b = bigsuds.BIGIP(
	    hostname = bigip, 
	    username = username, 
	    password = userpass,
	    )
    except Exception, e:
	print e

############### START PROCESSING LOGIC  ##################

    
    ### LICENSE DEVICE ###
    
    # Misc EULA Variables #
    email  = settings_dict['email']
    firstName = settings_dict['firstName']
    lastName = settings_dict['lastName']
    companyName = settings_dict['companyName']
    phone = settings_dict['phone']
    jobTitle = settings_dict['jobTitle']
    address = settings_dict['address']
    city = settings_dict['city']
    stateProvince = settings_dict['stateProvince']
    postalCode = settings_dict['postalCode']
    country = settings_dict['country']

    # License Variables #
    reg_keys = settings_dict['reg_keys']
    reg_keys_string = settings_dict['reg_keys_string']
    license_string = settings_dict['license_string']
    eula_string = settings_dict['eula_string']
    local_license_file_name = settings_dict['local_license_file_name']
    local_eula_file_name = settings_dict['local_eula_file_name']
    license_server_hostname = settings_dict['license_server_hostname']

    # DEVICE CERTIFICATE VARIABLES: #
    cert_email = settings_dict['cert_email']
    cert_country = settings_dict['cert_country']
    cert_state = settings_dict['cert_state']
    cert_locality = settings_dict['cert_locality']
    cert_organization = settings_dict['cert_organization']
    cert_division = settings_dict['cert_division']
    cert_expire = settings_dict['cert_expire']
# 
#     if local_license_file_name:
# 	try:
# 	    print "Attempting to retrive License from local disk ..."
# 	    with open(local_license_file_name, 'r') as fh_license:
# 		license_string = fh_license.read()
# 
# 	except:
# 	    print "Can't Open license file named: \"" + local_license_file_name + "\" on disk."
# 	     #sys.exit()
# 	    print "No worries. Will attempt to retrieve one from online."
# 
# 
#     if not license_string:
# 
# 	print "Attempting to get license online."
# 	print "License server requires you to submit EULA."
# 	if local_eula_file_name:
# 	    print "Attempting to retrive EULA from local disk first..."
# 	    try:
# 		with open(local_eula_file_name, 'r') as fh_eula:
# 		    eula_string = fh_eula.read()
# 
# 	    except:
# 		print "Can't find EULA file named : \"" +  local_eula_file_name + "\" on disk."
# 		print "No worries. Will attempt to retrieve one during transaction with License Server."
# 
#     #Could also try seeing if Target BIGIP has one stored
#     ### eula_file = get_eula_file(b)
# 
# 
#     if reg_keys_string:
# 	reg_keys = reg_keys_string.split(",")
# 	print "reg keys provided"  
# 	print reg_keys
# 
#     if len(reg_keys) < 1:
# 	    print "Reg Key list is empty, attempting to retrieve existing keys from the unit"
# 	    reg_keys = get_reg_keys(b)
# 
# 
#     print "Getting dossier using keys:" + str(reg_keys)
#     dossier_string = get_dossier( b, reg_keys )
#     #print "dossier = " + str(dossier_output)
# 
# 
#     license_string = get_license_from_F5_License_Server(
# 							license_server_hostname,
# 							dossier_string, 
# 							eula_string, 
# 							email, 
# 							firstName,
# 							lastName,
# 							companyName, 
# 							phone, 
# 							jobTitle, 
# 							address, 
# 							city, 
# 							stateProvince, 
# 							postalCode, 
# 							country
# 							)
# 
#     if license_string:
# 	print "License Found. Attempting to installing License on BIGIP:"
# 	install_license ( b, license_string )
#     else:
# 	print "Sorry. Could not retrieve License. Check your connection"
# 
#     license_status = get_license_status ( b )
#     print "License status = " + license_status
# 
#     #Need to let suds client catch up
#     print "Sleeping for 5 seconds.... Please be patient"
#     time.sleep(5)
# 
#     ### START CONFIGURING THE DEVICE ###
#     print "\n\nSetting Hostname to " + hostname
#     set_hostname( b, hostname )
#     print "\nGetting Hostname"
#     get_hostname( b )
#     
# 
#     # WARNING: If changing Provisioning from default LTM Nominal
#     # it may require rebooting 
#     # However, need to do first in order to configure various base settings
#     provision_dict = dict(config['SYSTEM']['PROVISIONING'])
#     modules = []
#     module_names = []
#     for k in provision_dict:
# 	#print "After Key: \"" + k + "\"   Value: \"" + provision_dict[k] + "\""
# 	modules.append({ k : provision_dict[k]})   
# 	module_names.append(k)   
# 
#     print "\n\nSetting Provisioning:"
#     set_provision( b, modules )
#     time.sleep(15)
#     print "\nGetting Provisioning:"
#     get_provision( b, module_names )
# 
#     #Will upload a third party cert. 
#     print "\n\nUpdating Device Certificate..."
#     src_file_name = "configs/bigip-1.p12"
#     dest_file_name = "/var/tmp/bigip-1.p12"
#     upload_file (b, src_file_name, dest_file_name )
#     
#     p12_password = "password"
#     file_location_on_bigip = dest_file_name
#     install_management_cert( b, p12_password, file_location_on_bigip ) 
# 
# #     cert_mode = "MANAGEMENT_MODE_WEBSERVER" 
# #     cert_id = "server"
# #     generate_certificate(   b, cert_mode, cert_id, cert_email,  
# # 			    hostname, cert_country, cert_state, cert_locality, 
# # 			    cert_organization, cert_division, cert_expire )
# # 
# #     #Retrieve Device Cert
# #     print "\nRetrieving new Device Cert..."
# #     my_cert_pem = certificate_export_to_PEM( b, cert_mode, cert_id )
# # 
#       
#     #Upload it back to /config/big3d/client.crt"
#     #Changing Trusted Device Certificates:
#     #Caution, this could be a bundle so only run once on lab setups before bigip_adds, etc.
#     #print my_cert_pem
#     #print "Uploading new Device Cert to BIG3D."
#     #cert_mode = "MANAGEMENT_MODE_IQUERY_BIG3D"; 
#     #cert_id = "client";
#     #certificate_import_from_PEM( b, cert_mode, cert_id, my_cert_pem )
# 
# 
#     # Not used now as don't want any custom sys settings
#     # sys_dict = dict(config['SYSTEM'])
#     # sys_fields = sys_dict
#     # print "Setting SYS Config: " 
#     # set_system_config (b, sys_fields )
#     # print "Getting SYS Config: " 
#     # get_LTConfig_field_values ( b, 'system', sys_fields ) 
# 
#     # python format for iControl
#     # [{'name': 'Arp.GratuitousRate', 'value': '0'}, {'name': 'Setup.Run', 'value': 'true'}]
#     # however, send them in an array of hashes and just have function format them for iControl
#     # [{ db_key_name_1 : db_key_value_1 } , { db_key_name_2 :  db_key_value_2 } ]
# 
# 
#     db_keys_dict = dict(config['SYSTEM']['DB_KEYS'])
#     db_keys = []
#     db_key_names = [] 
#     for k in db_keys_dict:
# 	#print "Before Key: \"" + k + "\"   Value: \"" + db_keys_dict[k] + "\""
# 	#db_keys_dict[k]=db_keys_dict[k].split("#",1)[0].strip('\" ') # To get rid of inline comments
# 	#print "After Key: \"" + k + "\"   Value: \"" + db_keys_dict[k] + "\""
# 	db_keys.append({ k : db_keys_dict[k]})   
# 	db_key_names.append(k)   
# 
#     print "\n\nSetting DB Keys"
#     modify_db_keys( b, db_keys )
#     print "\nGetting DB Keys:"
#     get_db_keys( b, db_key_names )
# 
#     ntp_dict = dict(config['SYSTEM']['NTP'])
#     #ntp_servers = ntp_servers
#     ntp_fields = { 'servers'     : ntp_dict['servers'] }
#     print "\n\nSetting NTP Config to servers: " + str(ntp_dict['servers']) + "\n"
#     #set_ntp_servers( b, ntp_servers )
#     set_ntp_config( b, ntp_fields )
#     print "\nGetting NTP Config: "
#     get_ntp_config( b, ntp_fields ) 
# 
#     dns_dict = dict(config['SYSTEM']['DNS'])
#     dns_fields = { 'nameservers'     : dns_dict['nameservers'] }
#     print "\n\nSetting DNS Config: "
#     set_dns_config( b, dns_fields )
#     print "\nGetting DNS Config: "
#     get_dns_config( b, dns_fields ) 
# 
#     sshd_dict = dict(config['SYSTEM']['SSH'])
#     sshd_fields = sshd_dict
#     print "\n\nSetting SSH Config: " 
#     set_sshd_config( b, sshd_fields )
#     print "\nGetting SSH Config: " 
#     get_sshd_config( b, sshd_fields ) 
# 
#     mcpd_dict = dict(config['SYSTEM']['MCPD'])
#     mcpd_fields = mcpd_dict
#     print "\n\nSetting MCPD Config: " 
#     set_mcpd_config( b, mcpd_fields )
#     print "\nGetting MCPD Config: " 
#     get_mcpd_config( b, mcpd_fields ) 
# 
#     cli_dict = dict(config['SYSTEM']['CLI'])
#     cli_fields = cli_dict
#     print "\n\nSetting CLI Config: " 
#     set_cli_config ( b, cli_fields  )
#     print "\nGetting CLI Config: " 
#     get_cli_config( b, cli_fields ) 
#  
#     httpd_dict = dict(config['SYSTEM']['HTTP'])
#     httpd_fields = { 
# 		     'include'			: httpd_dict['include'],
# 		     'allow'			: httpd_dict['allow'],
# 		     'authpamidletimeout'	: httpd_dict['authpamidletimeout'] 
# 		   }
#     print "\n\nSetting HTTP Config: "
#     set_httpd_config( b, httpd_fields )
#     print "\nGetting HTTP Config: "
#     get_httpd_config( b, httpd_fields )
# 
#      
#     syslog_dict = dict(config['SYSTEM']['SYSLOG'])
#     #syslog_fields = syslog_dict
#     syslog_fields = { 'include'     : syslog_dict['include'] }
#     print "\n\nSetting SYSLOG Config: " 
#     set_syslog_config( b, syslog_fields )
#     print "\nGetting SYSLOG Config: " 
#     get_syslog_config( b, syslog_fields ) 
# 
# 
    snmp_dict = dict(config['SYSTEM']['SNMP'])
    snmp_dict = dict(config['SYSTEM']['SNMP']['SNMP_VARS'])
    snmp_ltconfig_dict = dict(config['SYSTEM']['SNMP']['SNMP_VARS_LTCONFIG'])
    # snmp_trap2sink_dict = dict(config['SYSTEM']['snmp']['SNMP_TRAP2SINK'])
    # snmp_trapsess_dict = dict(config['SYSTEM']['snmp']['SNMP_TRAPSESS'])
    # print "Setting SNMP Config Client Access:" 
    # set_snmp_config ( b, snmp_fields )
    # get_LTConfig_field_values ( b, 'snmpd', snmp_fields ) 
    # 
    # 
#     # print "Setting SNMP trap2sess Config"  
#     # set_snmp_trapsess_config( b, 
#     #                             [ snmp_trapsess_host_value_1, snmp_trapsess_host_value_2   ], 
#     #                             [ snmp_trapsess_fields,       snmp_trapsess_fields         ], 
#     #                             [ snmp_trapsess_values_1,     snmp_trapsess_values_2       ] )
#     # 
#     # 
#     # print "Getting SNMP trapsess Config General"  
#     # get_snmp_trapsess_config ( b, snmp_trapsess_fields_all )
#     # #print "Getting SNMP trapsess Config from Classes"  
#     # #get_field_values_from_custom_class_list ( b, [snmp_trapsess_class_name_1,snmp_trapsess_class_name_2], [ snmp_trapsess_fields, snmp_trapsess_fields ])
#     # 
#     # set_snmp_trap2sink_config( b, snmp_trap2sink_fields_all, snmp_trap2sink_values_all ) 
#     # 
#     # #### bug in batch upload so need to do one at a time #####
#     # #### set_snmp_config_trap2sinks(b, trap2sink_hosts, trap2sink_ports, trap2sink_communities )
#     # #### bug in batch upload so need to do one at a time in two seperate calls #####.
# 
#     # set_snmp_config_trap2sinks(b, [snmp_trap2sink_1_host], [snmp_trap2sink_1_port], [snmp_trap2sink_1_community] )
#     # set_snmp_config_trap2sinks(b, [snmp_trap2sink_2_host], [snmp_trap2sink_2_port], [snmp_trap2sink_2_community] )
#     # 
#     # 
#     # # ALTERNATIVE INTERFACE USING NATIVE MANAGEMENT METHODS
#     # # set_snmp_config_client_access(obj, snmp_allow_networks, snmp_allow_masks)
#     # 
#     # #print "Setting SNMP Config System information:" 
#     # # set_snmp_config_system_info (   b, 
#     #                                 # snmp_sys_name, 
#     #                                 # snmp_sys_location, 
#     #                                 # snmp_sys_contact, 
#     #                                 # snmp_sys_description, 
#     #                                 # snmp_sys_object_id, 
#     #                                 # snmp_sys_services 
#     #                             # )
#     # 
#     # print "Getting SNMP Config" 
#     # get_snmp_config_system_info (b)
#     # 
#     # 
# 
#     #system_auth_dict = dict(config['SYSTEM']['SYSTEM_AUTH'])
#     #print "Setting RADIUS SERVERS:"
#     #set_radius_server ( b, radius_server_name_1, radius_server_ip_1, radius_server_port_1, radius_secret_1 )
#     #set_radius_server ( b, radius_server_name_2, radius_server_ip_2, radius_server_port_2, radius_secret_2 )
# 
#     #print "Setting RADIUS CONFIG:"
#     #set_radius_config( b, "system-auth", [ radius_server_name_1, radius_server_name_2 ] )
#     # 
#     # print "Setting TACACS CONFIG:"
#     # set_tacacs_config( b, "system-auth", tacacs_secret, tacacs_service_name, tacacs_protocol_name, [ tacacs_server_ip_1, tacacs_server_ip_2 ] )
#     
#     #print "Setting Additional SYSTEM AUTH Config:"
#     #Methods use official Management.UserManagement 
#     #set_system_auth_default_role( b, system_auth_role )
#     #set_system_auth_default_partition( b, system_auth_partition )
#     #set_system_auth_console_access( b, system_auth_console 
#     #set_system_auth_default_shell( b, system_auth_shell )    ### Doesn't work as can't see remote_user ####
# 
#     #LTConfig Methods :
#     #set_system_auth_remote_users_config( b, system_auth_fields_all, system_auth_values_all )    #get_LTConfig_field_values ( b, 'remote_users', system_auth_fields_all ) 
# 
# 
#     #Set AD Config
#     ad_config = dict(config['SYSTEM']['SYSTEM_AUTH']['ACTIVE_DIRECTORY'])
#     server = ad_config['server']
#     base_dn = ad_config['base_dn']
#     bind_dn = ad_config['bind_dn']
#     bind_pass = ad_config['bind_pass']
#     print "\n\nSetting System Auth to AD"
#     set_system_auth_ad_config( b, server, base_dn, bind_dn, bind_pass )   
# 
#     #Set Remote Roles
#     remote_roles_dict = dict(config['SYSTEM']['SYSTEM_AUTH']['REMOTE_ROLES'])
#     roles = {}
#     for k,v in remote_roles_dict.items():
# 	roles[k] = v
#     print "\n\nSetting Remote Roles" 
#     set_remote_roles( b, roles )
#  
# 
#     ######### BEGIN NETWORK CONFIG  ################
# 
#     #network_dict = dict(config['NETWORK'])
# 
#     #Set Management Routes
#     mgmt_routes_dict = dict(config['NETWORK']['MGMT_ROUTES'])
#     management_route_names = []
#     management_route_nets = []
#     management_route_masks = []
#     management_route_gws = []
#     for k,v in mgmt_routes_dict.items():
# 	management_route_names.append( k )
# 	management_route_nets.append( v['net'] )
# 	management_route_masks.append( v['mask'] )
# 	management_route_gws.append( v['gw'] )
# 
#     #print "\n\nSetting Management Routes"
#     #set_management_routes( b, management_route_names, management_route_nets, management_route_masks, management_route_gws )
#     #print "\nGetting Management Routes"
#     #get_management_routes( b )
# 
#     # Set Trunks
#     #trunks_dict = dict(config['NETWORK']['TRUNKS'])
#     #print "Setting Trunks:"
#     #set_trunk( b, trunk_name, interfaces, lacp_enabled, lacp_timeout, lacp_active_state )
#     #get_trunk( b ) 
# 
# 
#     # Set Vlans
#     vlans_dict = dict(config['NETWORK']['VLAN'])
#     vlan_names = []
#     vlan_ids = []
#     vlan_members = []
#     vlan_tagged_states = []
#     vlan_failsafe_states = []
#     vlan_failsafe_timeouts = []
#     #mac_masq deprecated for traffic groups
#     vlan_mac_masquerade_addresses  = []
#     for k,v in vlans_dict.items():
# 	vlan_names.append( k )
# 	vlan_ids.append( v['tag'] )
# 	vlan_members.append( v['interfaces'] )
# 	vlan_tagged_states.append( v['tagged'] )
# 	vlan_failsafe_states.append( v['failsafe'] )
# 	vlan_failsafe_timeouts.append( v['failsafe_timeout'] )
# 	vlan_mac_masquerade_addresses.append( v['mac_masquerade'] )
# 
#     print "\n\nSetting Vlans:"
#     set_vlans( b, vlan_names, vlan_ids, vlan_members, vlan_tagged_states, vlan_failsafe_states, vlan_failsafe_timeouts, vlan_mac_masquerade_addresses )
#     print "\nGetting Vlans:"
#     get_vlans( b )
# 
#     #Set Selfs
#     self_ips_dict = dict(config['NETWORK']['SELF_IPS'])
#     self_ip_names = []
#     self_ip_addresses = []
#     self_ip_netmasks = []
#     self_ip_vlan_names = []
#     self_ip_traffic_groups = []
#     self_ip_floating_states = []
#     self_ip_port_lockdown_list = []
#     self_ip_port_custom_add = []
#     self_mac_masquerade_addresses  = []
# 
#     for k,v in self_ips_dict.items():
#         self_ip_names.append( k )
#         self_ip_addresses.append( v['address'] )
#         self_ip_netmasks.append( v['netmask'] )
#         self_ip_vlan_names.append( v['vlan'] )
#         self_ip_traffic_groups.append( v['traffic_group'] )
#         self_ip_floating_states.append( v['floating_state'] )
#         self_ip_port_lockdown_list.append( v['port_lockdown'] )
#         self_ip_port_custom_add.append( v['port_custom_add'] )
# 
#     print "\n\nSetting Self IPs:"
#     set_self_ips( b, self_ip_names, self_ip_addresses, self_ip_netmasks, self_ip_vlan_names, self_ip_traffic_groups, self_ip_floating_states, self_ip_port_lockdown_list, self_ip_port_custom_add )
#     print "\nGetting Self IPs:"
#     get_self_ips( b )
# 
#     # #Set Static TMM Routes
#     routes_dict = dict(config['NETWORK']['ROUTES'])
#     route_names = []
#     route_nets = []
#     route_masks = []
#     route_gws = []
#     for k,v in routes_dict.items():
# 	route_names.append( k )
# 	route_nets.append( v['net'] )
# 	route_masks.append( v['mask'] )
# 	route_gws.append( v['gw'] )
# 
#     print "\n\nSetting Routes: "
#     set_static_routes( b, route_names, route_nets, route_masks, route_gws )
#     print "\nGetting Routes: "
#     #get_static_routes( b )
#     get_static_routes( b )
# 
# 
#     #Set Gateway Pools
#     print "\n\nSetting Gateway Pools: "
#     set_gateway_pools( b, self_ip_addresses, self_ip_netmasks, self_ip_vlan_names  )
#     print "\nGetting Gateway Pools: "
#     get_gateway_pools( b )
# 
# 
#     print "\n\nFINISHED DEPLOYING NODE!\n"
#     # TO DO:
#     # SOFTWARE
#     # Files, ZebOS.conf
# 
# 
# 




