#!/bin/bash

nginx_conf="./nginx-proxy.conf"

line_number=4
spaces="        "
# # Durchlaufe alle .pem-Dateien im Verzeichnis
for cert in $(/usr/bin/find . -path **/auth/TLS.pem)
do
    # Erstelle einen Fingerabdruck für jede .pem-Datei
    fingerprint=$(openssl x509 -in "$cert" -noout -fingerprint -sha1 | sed 's/SHA1 Fingerprint=//')
    # Füge den Fingerabdruck zur map-Direktive hinzu
    sed -i "${line_number}i${spaces}sha1 ${fingerprint} 0;" "$nginx_conf"
    ((line_number++))
done