#!/bin/bash

#Variables defined by user
clientcerts=5
binarylocation=/usr/bin
ssldir=$PWD
password=password

#Files required by script
sslcnf1=ca-openssl.cnf
sslcnf2=intermediate-openssl.cnf



#Put all files in general bucket for bigip use. Everything should be in here for easy export
mkdir $ssldir/bigip

#Make directories for CA files
mkdir $ssldir/ca 
mkdir $ssldir/ca/requests
mkdir $ssldir/ca/newcerts
mkdir $ssldir/ca/certs
mkdir $ssldir/ca/crl
touch $ssldir/ca/index.txt
echo "01" > $ssldir/ca/serial 

#Make directories for Intermediate CA
mkdir $ssldir/int
mkdir $ssldir/int/requests
mkdir $ssldir/int/newcerts
mkdir $ssldir/int/certs
mkdir $ssldir/int/crl
touch $ssldir/int/index.txt 
echo "01" > $ssldir/int/serial 
#Put all certs signed by Intermediate CA in here
mkdir $ssldir/int/certs
mkdir $ssldir/int/keys 

#chmod 700 $ssldir 
export SSLDIR=$ssldir 



###########################################################
###                CREATE ROOT CA                       ###
###########################################################


echo "----------------------------------------------------"
echo "-- generate Root CA cert and key"
echo "----------------------------------------------------"

$binarylocation/openssl req -config $ssldir/$sslcnf1 -new -x509 -days 3652 -extensions v3_ca -sha1 -newkey rsa:2048 -nodes -keyout $SSLDIR/ca/ca.key -out $SSLDIR/ca/ca.crt -subj '/DC=com/DC=example/L=Seattle/ST=WA/C=US/CN=rootca.example.com' 


#Create Der format for LDAP import
$binarylocation/openssl x509 -in $ssldir/ca/ca.crt -out $ssldir/ca/ca.der -outform DER



echo "----------------------------------------------------"
echo "-- generate a crl for Root CA"
echo "----------------------------------------------------"
$binarylocation/openssl ca -config $ssldir/$sslcnf1 -gencrl -crlexts crl_ext -md sha1 -out $ssldir/ca/crl/ca-crl.pem

#Create Der format for LDAP import
$binarylocation/openssl crl -in $ssldir/ca/crl/ca-crl.pem -out $ssldir/ca/crl/ca-crl.der -outform DER 



###########################################################
### Now let's move on to the Intermediate CA            ###
###########################################################


echo "----------------------------------------------------"
echo "-- generate Intermediate Root CA cert and key"
echo "----------------------------------------------------"


$binarylocation/openssl req -new -sha1 -newkey rsa:1024 -nodes -keyout $ssldir/int/intermediate-ca.key -subj '/DC=com/DC=example/L=Seattle/ST=WA/C=US/CN=intermediate-ca.example.com' -out $ssldir/ca/requests/intermediate-ca.req

yes "y\n" | $binarylocation/openssl ca -config $ssldir/$sslcnf1 -days 1865 -extensions v3_ca -out $ssldir/int/intermediate-ca.crt -infiles $ssldir/ca/requests/intermediate-ca.req

#Create Der format for LDAP import
$binarylocation/openssl x509 -in $ssldir/int/intermediate-ca.crt -out $ssldir/int/intermediate-ca.der -outform DER



echo "----------------------------------------------------"
echo "-- generate Website cert and key"
echo "----------------------------------------------------"

$binarylocation/openssl req -new -sha1 -newkey rsa:1024 -nodes -keyout $ssldir/int/keys/website.key -subj '/DC=com/DC=example/L=Seattle/ST=WA/C=US/CN=*.example.com' -out $ssldir/int/requests/website.req
yes "y\n" | $binarylocation/openssl ca -config $ssldir/$sslcnf2 -days 1865 -extensions ssl_server -out $ssldir/int/certs/website.pem -infiles $ssldir/int/requests/website.req

#clean up pem for apache. get rid of text outputi
$binarylocation/openssl x509 -in $ssldir/int/certs/website.pem -out $ssldir/int/certs/website.crt 

#Create pkcs for potential export
$binarylocation/openssl pkcs12 -export -in $ssldir/int/certs/website.crt -name "website-pkcs12" -inkey $ssldir/int/keys/website.key -passout pass:$password -out $ssldir/int/certs/website-pkcs12.p12 


###########################################################
###          START GENERATING CLIENT CERTS             ####
###########################################################


for ((i=1;i<=$clientcerts;i++)); do


echo "----------------------------------------------------"
echo "-- generate client$i cert request and key"
echo "----------------------------------------------------"
$binarylocation/openssl req -new -sha1 -newkey rsa:1024 -nodes -keyout $ssldir/int/keys/client$i.key -subj "/DC=com/DC=example/OU=people/L=Seattle/ST=WA/C=US/emailAddress=client$i@example.com/CN=client$i" -out $ssldir/int/requests/client$i.req

# NOTE: EMAIL ADDRESS SYNTAX MAY CHANGE DEPENDING ON OPENSSL VERSION

yes "y\n" | $binarylocation/openssl ca -config $ssldir/$sslcnf2 -days 1865 -extensions ssl_client -out $ssldir/int/certs/client$i.crt -infiles $ssldir/int/requests/client$i.req

#Convert to DER format for LDAP import
$binarylocation/openssl x509 -in $ssldir/int/certs/client$i.crt -out $ssldir/int/certs/client$i.der -outform DER

#Generate pkcs12 cert for web browser"
$binarylocation/openssl pkcs12 -export -in $ssldir/int/certs/client$i.crt -out $ssldir/int/certs/client$i.p12 -name "client$i browser pkcs12 cert" -inkey $ssldir/int/keys/client$i.key -passout pass:$password


done


echo "----------------------------------------------------"
echo "-- generate 512 client6 cert request and key"
echo "----------------------------------------------------"

$binarylocation/openssl req -new -sha1 -newkey rsa:512 -nodes -keyout $ssldir/int/keys/client6.key -subj "/DC=com/DC=example/OU=people/L=Seattle/ST=WA/C=US/emailAddress=client6@example.com/CN=client6" -out $ssldir/int/requests/client6.req

yes "y\n" | $binarylocation/openssl ca -config $ssldir/$sslcnf2 -days 1865 -extensions ssl_client -out $ssldir/int/certs/client6.crt -infiles $ssldir/int/requests/client6.req

#Convert to DER format for LDAP import
$binarylocation/openssl x509 -in $ssldir/int/certs/client6.crt -out $ssldir/int/certs/client6.der -outform DER

#Generate pkcs12 cert for web browser"
$binarylocation/openssl pkcs12 -export -in $ssldir/int/certs/client6.crt -out $ssldir/int/certs/client6.p12 -name "client6 browser pkcs12 cert" -inkey $ssldir/int/keys/client6.key -passout pass:$password


echo "----------------------------------------------------"
echo "-- generate 2048 client7 cert request and key"
echo "----------------------------------------------------"

$binarylocation/openssl req -new -sha1 -newkey rsa:2048 -nodes -keyout $ssldir/int/keys/client7.key -subj "/DC=com/DC=example/OU=people/L=Seattle/ST=WA/C=US/emailAddress=client7@example.com/CN=client7" -out $ssldir/int/requests/client7.req

yes "y\n" | $binarylocation/openssl ca -config $ssldir/$sslcnf2 -days 1875 -extensions ssl_client -out $ssldir/int/certs/client7.crt -infiles $ssldir/int/requests/client7.req

#Convert to DER format for LDAP import
$binarylocation/openssl x509 -in $ssldir/int/certs/client7.crt -out $ssldir/int/certs/client7.der -outform DER

#Generate pkcs12 cert for web browser"
$binarylocation/openssl pkcs12 -export -in $ssldir/int/certs/client7.crt -out $ssldir/int/certs/client7.p12 -name "client7 browser pkcs12 cert" -inkey $ssldir/int/keys/client7.key -passout pass:$password


echo "----------------------------------------------------"
echo "-- generate 4096 client8 cert request and key"
echo "----------------------------------------------------"

$binarylocation/openssl req -new -sha1 -newkey rsa:4096 -nodes -keyout $ssldir/int/keys/client8.key -subj "/DC=com/DC=example/OU=people/L=Seattle/ST=WA/C=US/emailAddress=client8@example.com/CN=client8" -out $ssldir/int/requests/client8.req

yes "y\n" | $binarylocation/openssl ca -config $ssldir/$sslcnf2 -days 1885 -extensions ssl_client -out $ssldir/int/certs/client8.crt -infiles $ssldir/int/requests/client8.req

#Convert to DER format for LDAP import
$binarylocation/openssl x509 -in $ssldir/int/certs/client8.crt -out $ssldir/int/certs/client8.der -outform DER

#Generate pkcs12 cert for web browser"
$binarylocation/openssl pkcs12 -export -in $ssldir/int/certs/client8.crt -out $ssldir/int/certs/client8.p12 -name "client8 browser pkcs12 cert" -inkey $ssldir/int/keys/client8.key -passout pass:$password






###########################################################
#Comment out if you don't want to revoke client1's certificate
###########################################################

#echo "----------------------------------------------------"
#echo "-- revoke client1's certificate for testing"
#echo "----------------------------------------------------"
#yes "y\n" | $binarylocation/openssl ca -config $ssldir/$sslcnf2 -revoke $ssldir/int/newcerts/02.pem

###########################################################



echo "----------------------------------------------------"
echo "-- generate a crl for the Intermediate CA"
echo "----------------------------------------------------"
$binarylocation/openssl ca -config $ssldir/$sslcnf2 -gencrl -crlexts crl_ext -md sha1 -out $ssldir/int/crl/intermediate-crl.pem

#Convert crl to DER format for LDAP import"
$binarylocation/openssl crl -in $ssldir/int/crl/intermediate-crl.pem -out $ssldir/int/crl/intermediate-crl.der -outform DER 


#Copy all files needed for bigip 
cp $ssldir/ca/ca* $ssldir/bigip
cp $ssldir/ca/crl/* $ssldir/bigip
cp $ssldir/int/int* $ssldir/bigip
cp $ssldir/int/crl/* $ssldir/bigip
cp $ssldir/int/keys/* $ssldir/bigip
cp $ssldir/int/certs/* $ssldir/bigip

#create a bundle of Root and Intermediate
cat $ssldir/bigip/ca.crt >> $ssldir/bigip/custom-ca-bundle.crt
cat $ssldir/bigip/intermediate-ca.crt >> $ssldir/bigip/custom-ca-bundle.crt

##################################################################
#As curl needs one file for client cert and key, cat some together
# ex. curl -E curl-client2-good --cacert custom-ca-bundle.crt https://www.example.com
###################################################################

cat $ssldir/bigip/client1.crt >> $ssldir/bigip/curl-client1-1024-revoked
cat $ssldir/bigip/client1.key >> $ssldir/bigip/curl-client1-1024-revoked

cat $ssldir/bigip/client2.crt >> $ssldir/bigip/curl-client2-1024-good
cat $ssldir/bigip/client2.key >> $ssldir/bigip/curl-client2-1024-good

cat $ssldir/bigip/client6.crt >> $ssldir/bigip/curl-client6-512
cat $ssldir/bigip/client6.key >> $ssldir/bigip/curl-client6-512

cat $ssldir/bigip/client7.crt >> $ssldir/bigip/curl-client7-2048
cat $ssldir/bigip/client7.key >> $ssldir/bigip/curl-client7-2048

cat $ssldir/bigip/client8.crt >> $ssldir/bigip/curl-client8-4096
cat $ssldir/bigip/client8.key >> $ssldir/bigip/curl-client8-4096

echo "----------------------------------------------------"
echo "-- done"
echo "----------------------------------------------------"




