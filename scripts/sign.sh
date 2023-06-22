#!/bin/bash
set -e

CASDIR=$(realpath $@)
if [[ ! -d $CASDIR ]]; then
    echo "Usage: ${BASH_SOURCE[0]} /path/to/private/key/directory"
    echo "       Missing first parameter is path to directory containing private keys"
    exit 1
fi

BASENAME=/usr/bin/basename
KEYTYPESTOSIGN=("onboarding")
CURRDIR=$PWD


declare -A USAGETOSIGNINGCA=(
 [auth]="$CASDIR/cas/TLS/certs/TNG_TLS.pem"
 [TLS]="$CASDIR/cas/TLS/certs/TNG_TLS.pem"
 [csca]="$CASDIR/cas/TA/certs/TNG_TA.pem"
 [SCA]="$CASDIR/cas/TA/certs/TNG_TA.pem"
)
declare -A USAGETOSIGNINGKEY=(
 [auth]="$CASDIR/cas/TLS/private/TNG_TLS.key.pem"
 [TLS]="$CASDIR/cas/TLS/private/TNG_TLS.key.pem"
 [csca]="$CASDIR/cas/TA/private/TNG_TA.key.pem"
 [SCA]="$CASDIR/cas/TA/private/TNG_TA.key.pem"
)
declare -A USAGETOSIGNINGCFG=(
 [auth]="$CASDIR/cas/TLS/openssl.conf"
 [TLS]="$CASDIR/cas/TLS/openssl.conf"
 [csca]="$CASDIR/cas/TA/openssl.conf"
 [SCA]="$CASDIR/cas/TA/openssl.conf"
 )

ROOT=$(realpath $(dirname $(dirname ${BASH_SOURCE[0]})))
echo "Examining contents of $ROOT";
for DIR in $ROOT/*
do
    if [[ ! -d $DIR || -L $DIR ]]; then continue; fi #not a directory 
    ISO3=$($BASENAME "$DIR")
    if [[ "${ISO3}" == "WHO" ]]; then continue; fi #Skip WHO keys
    echo "Processing Folder: ${ISO3}"
    for KEYDIR in $DIR/*
    do
	if [[ ! -d $KEYDIR || -L $KEYDIR ]]; then continue; fi #not a directory 
	KEYTYPE=$($BASENAME "$KEYDIR")
	if [[ ! ${KEYTYPESTOSIGN[@]} =~ $KEYTYPE ]]; then continue; fi
	echo "  Found Key Type: $KEYTYPE";

	for DOMAINDIR in $KEYDIR/*		     
	do
	    if [[ ! -d $DOMAINDIR ||  -L $DOMAINDIR ]]; then continue; fi #not a directory 
	    DOMAIN=$($BASENAME "$DOMAINDIR")
	    echo "    Found Domain: $DOMAIN";
	    for USAGEDIR in $DOMAINDIR/*/
	    do
		if [[ ! -d $USAGEDIR ||  -L $USAGEDIR ]]; then continue; fi #not a directory 
		USAGE=$($BASENAME "$USAGEDIR")
		if [ ! "${USAGETOSIGNINGKEY[$USAGE]+isset}" ]; then continue; fi #don't know what to sign with
		SIGNINGKEY=$PRIVATEKEYDIR/${USAGETOSIGNINGKEY[$USAGE]}
		SIGNINGCA=$PRIVATEKEYDIR/${USAGETOSIGNINGCA[$USAGE]}
		SIGNINGCFG=$PRIVATEKEYDIR/${USAGETOSIGNINGCFG[$USAGE]}
		if [ ! -e "$SIGNINGKEY" ]; then
		   echo "Error: Could not find $SIGNINGKEY"
		   exit 2
		fi;
		echo "      Found Key Usage: $USAGE signing with $SIGNINGKEY";
		SIGNEDDIR=$USAGEDIR/signed
		mkdir -p $SIGNEDDIR
		for CERTPATH in $USAGEDIR/*.pem
		do
		    CERT=$($BASENAME "${CERTPATH}")
		    SIGNEDCERT=signed.$CERT
		    CSR=$CERT.csr
		    SIGNEDTXT=signed.${CERT%.pem}.txt
		    SIGNEDCERTPATH=$SIGNEDDIR/$SIGNEDCERT
		    SIGNEDTXTPATH=$SIGNEDDIR/$SIGNEDTXT
		    CSRPATH=$SIGNEDDIR/$CSR
		    echo "        Signing CERT $KEY with $SIGNINGCA "
		    echo "           x509 Output At: $SIGNEDCERTPATH"
		    echo "           Text Output At: $SIGNEDTXTPATH"
		    cd $CASDIR
		    SUBJ=`openssl x509 -in $CERTPATH -noout -subject --nameopt multiline | tail -n +2 | sed 's/^\s*/\//' | sed 's/\s*=\s*/=/' |sed -z 's/\n//g'`
		    openssl req -out ${CSRPATH} -key ${SIGNINGKEY} -new  -subj "${SUBJ}" 
		    openssl ca -batch -create_serial -config $SIGNINGCFG -cert $SIGNINGCA -keyfile $SIGNINGKEY \
			    -in $CSRPATH -out $SIGNEDCERTPATH   -subj "${SUBJ}"  2>&1 | sed 's/^/            /g'

		    cd $CURRDIR
		    echo TrustAnchor Signature: > $SIGNEDTXTPATH
		    echo `openssl x509 -in $SIGNEDCERTPATH -noout -text -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame | tail -n +2| sed -z 's/\n*//g' | sed 's/\s*//g' | sed 's/://g' | xxd -r -p | base64 -w 0` \
			 >>  $SIGNEDTXTPATH
		    echo Certificate Raw Data: >> $SIGNEDTXTPATH
		    echo `openssl x509 -in $SIGNEDCERTPATH  | tail -n +2 | head -n -1 | sed -z 's/\n*//g' | sed 's/\s*//g'` >> $SIGNEDTXTPATH
		    echo Certificate Thumbprint: `openssl x509 -in $SIGNEDCERTPATH -noout -fingerprint | awk -F'=' '{print $2}' | sed 's/://g'` \
			 >>  $SIGNEDTXTPATH
		    echo Certificate Country: $ISO3 >>  $SIGNEDTXTPATH  #not two letter code!!!
		done
	    done
	done
  done
done


    # touch WHO/signing/DCC/TNG_$CA.txt
    # echo 

    # 	 >> WHO/signing/DCC/TNG_$CA.txt