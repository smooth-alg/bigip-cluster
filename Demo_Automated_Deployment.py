#!/usr/bin/env python

import sys
import time
import subprocess
#import shlex
#import thread
#import Queue
#Below not in standard lib
from optparse import OptionParser
import Demo_Base_Config
import Demo_Cluster
import Demo_Deploy_Apps

def usage():
    print "OPTIONS:"
    print "		-m 	<cluster_members>.	ex. \"bigip-1.example.com,bigip-2.example.com,bigip-3.example.com\""
    print "		-b 	deploy base configs"
    print "		-p 	run base deployments in parallel"
    print "		-c 	deploy cluster"
    print "		-a 	deploy apps"
    print "		NOTES: 	at least one of the -b,-c,-a are required"
    print "USAGE: "
    print "	ex. " + sys.argv[0] + " -b -p -c -a -m \"bigip-1.example.com,bigip-2.example.com,bigip-3.example.com\""
    print "	ex. " + sys.argv[0] + " -b -m \"bigip-1.example.com,bigip-2.example.com\""
    print "	ex. " + sys.argv[0] + " -c -m \"bigip-1.example.com,bigip-2.example.com\""
    print "	ex. " + sys.argv[0] + " -a -m \"bigip-1.example.com,bigip-2.example.com\""


def main():

    CONFIG_DIR="configs/"
    cluster_members = []
    demo_base_processes = []
    license = ""

    parser = OptionParser()
    parser.add_option("-m", "--members", action="store", type="string", dest="cluster_members", help="Comma seperated list of hostnames")
    parser.add_option("-p", "--parallel", action="store_true", dest="parallel", help="Set to run Base configs in parallel" )
    parser.add_option("-b", "--base", action="store_true", dest="base", help="Set to deploy Base configs")
    parser.add_option("-c", "--cluster", action="store_true", dest="cluster", help="Set to deploy Cluster")
    parser.add_option("-a", "--apps", action="store_true", dest="apps", help="Set to deploy Apps")
    parser.add_option("-l", "--license", action="store_false", dest="license", default=True, help="Set if want to skip licensing" )
    (options, args) = parser.parse_args()

    if len(sys.argv) < 2: 
	usage()
	sys.exit(0)

    if options.license:
	license = ""
    else:
	#Set the skip license argument.
	print "Skipping Licensing"
	license = "--license"
    	

    if options.cluster_members == "":
	print "Using default cluster_members: "
	cluster_members = [ "bigip1.example.com", "bigip2.example.com", "bigip3.example.com" ]
    else:
	cluster_members = options.cluster_members.split(",")
    
    #Make an seperate array for holding subprocesses = lenth of cluster members
    for i in range(len(cluster_members)):
	    demo_base_processes.append("process_placeholder")
    
    if options.base:

	print "Deploying Cluster Nodes..."
       
	for i in range( len(cluster_members) ) :
	    print "\nDeploying Cluster Node " + str(i + 1)
	    # Using static file names for now 
            # but need better convention/mapping of individual device config files. 
	    # i.e. names found in cluster-members argument/array + ".ini"
	    # or just every file found in dir foo, etc.
	    bigip_config_file = CONFIG_DIR + "bigip-" + str(i + 1) + "-config.ini"

	    if options.parallel:
		# Spin up subprocesses in parellel to speed up deployment
		# but potentially makes demo visually confusing 
		# as output from all processes are mixed (or would need ot be sent to own seperate log files - not implemented)
		#
		# Could also implement threading instead of sub processes 
		# http://stackoverflow.com/questions/14533458/python-threading-multiple-bash-subprocesses

		demo_base_processes[i] = subprocess.Popen(["python", "Demo_Base_Config.py", "--config", bigip_config_file, license ])
		print "Demo_Base_Config.py Instance #" + str(i+1) + " PID = " + str(demo_base_processes[i].pid) 

	    else:
		#Run Serially. 
		p = subprocess.Popen(["python", "Demo_Base_Config.py", "--config", bigip_config_file, license ])
		print "Demo_Base_Config.py Instance #" + str(i+1) + " PID = " + str(p.pid) 

		#And wait for each process to finish before moving on to the next
		while p.poll() == None:
		    time.sleep(1)
		    p.poll()
		(results, errors) = p.communicate()
		if errors == '':
		    return results
		else:
		    print errors


	#If run in parallel, wait for all these to terminate before moving on to creating cluster
	if options.parallel:
	    for i in range(len(demo_base_processes)):
		print "Waiting for cluster member " + str(i+1) + " process to finish"
		while demo_base_processes[i].poll() == None:
		    time.sleep(1)
		    demo_base_processes[i].poll()
		(results, errors) = demo_base_processes[i].communicate()
		if errors == '':
		    return results
		else:
		    print errors
    
    if options.cluster:

	print "Creating Cluster...."
     
	# list has to be IPs as Add Peer Device only accepts IPs (vs. hostnames )
	# hardcoding for now
	cluster_members_ips = [ "10.11.50.201", "10.11.50.202", "10.11.50.203" ]   

	cluster_members_list_string = ""
	for member in cluster_members_ips:
	    cluster_members_list_string = cluster_members_list_string + member + ","
	cluster_members_list_string = cluster_members_list_string.strip(",") 

	p_Cluster = subprocess.Popen(["python", "Demo_Cluster.py", "--bigips", cluster_members_list_string , "-f", "ha,external", "-m", "ha,external" ])
	print "Demo_Cluster.py PID = " + str(p_Cluster.pid) 
	while p_Cluster.poll() == None:
	    time.sleep(1)
	    p_Cluster.poll()
	(results, errors) = p_Cluster.communicate()
	if errors == '':
	    return results
	else:
	    print errors



    if options.apps:

	print "Deploying Apps..."
	app_file = CONFIG_DIR + "bigip-1-apps.ini"
	p_Apps = subprocess.Popen(["python", "Demo_Deploy_Apps.py", "--config", app_file ])
	print "Demo_Deploy_Apps.py PID = " + str(p_Apps.pid) 

	while p_Apps.poll() == None:
	    time.sleep(1)
	    p_Apps.poll()
	(results, errors) = p_Apps.communicate()
	if errors == '':
	    return results
	else:
	    print errors


    print "\n\nFINISHED DEPLOYMENT!\n\n"


if __name__ == "__main__":
    main()

