#!/bin/bash

nginx_conf="./nginx/proxy.conf"

# Durchlaufe alle .pem-Dateien im Verzeichnis
for cert in $(/usr/bin/find ../. -path **/TLS/* -name TLS*.pem)
do
    # Erstelle einen Fingerabdruck für jede .pem-Datei
    fingerprint=$(openssl x509 -in "$cert" -noout -fingerprint -sha1 | sed 's/SHA1 Fingerprint=//; s/://g')
    # Füge den Fingerabdruck zur map-Direktive hinzu
    echo "$fingerprint 1;" >> $nginx_conf
done

echo "}" >> $nginx_conf

cat ./nginx/proxy.conf