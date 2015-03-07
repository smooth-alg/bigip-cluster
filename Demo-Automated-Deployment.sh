#!/bin/bash

CONFIG_DIR=configs
ace_config=$1

echo "Using Ace Config ${ace_config}" 
echo "Deploying Cluster Nodes..."
for i in 1 2 3; 
do 
	echo -en "\nDeploying Cluster Node: $i \n"
	./Demo-Base-Config.py --config ${CONFIG_DIR}/bigip-${i}-config.ini
done

echo "Creating Cluster...."
./Demo-Cluster.py --bigips 10.11.51.211,10.11.51.212,10.11.51.213 -f ha,external -m ha,external

echo "Deploying Apps..."
#./Demo-Deploy-Apps.py --config ${CONFIG_DIR}/bigip-1-apps.ini


echo -en "\n\nFINISHED!\n\n"
