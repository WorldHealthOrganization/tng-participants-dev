#!/bin/bash

# output_file="fingerprints.txt"

# for cert in $(/usr/bin/find . -path **/auth/TLS.pem)
#     do
#         i=$(($i+1))
#         echo "Adding $cert to ${CA_BUNDLE_FILE}"
#         # Erstelle einen Fingerabdruck für jede .pem-Datei
#         fingerprint=$(openssl x509 -in "$cert" -noout -fingerprint -sha1)
#         # Schreibe den Fingerabdruck in die Ausgabedatei
#         echo "$fingerprint" >> "$output_file"
#     done

#find -name TLS.pem -exec ssh-keygen -lf {} ';'

# Setze den Pfad zur NGINX-Konfigurationsdatei
nginx_conf="./nginx-proxy.conf"

# Beginne die map-Direktive
# echo "map \$ssl_client_fingerprint \$reject {" >> "$nginx_conf"
# echo "    default 1;" >> "$nginx_conf"

# # Durchlaufe alle .pem-Dateien im Verzeichnis
# for cert in $(/usr/bin/find . -path **/auth/TLS.pem)
# do
#     # Erstelle einen Fingerabdruck für jede .pem-Datei
#     fingerprint=$(openssl x509 -in "$cert" -noout -fingerprint -sha1 | sed 's/SHA1 Fingerprint=//')
#     # Füge den Fingerabdruck zur map-Direktive hinzu
#     echo "    $fingerprint 0;" >> "$nginx_conf"
# done

# # Schließe die map-Direktive ab
# echo "}" >> "$nginx_conf"

# # Füge die server-Direktive hinzu
# echo "server {" >> "$nginx_conf"
# echo "    if (\$reject) { return 403; }" >> "$nginx_conf"
# echo "}" >> "$nginx_conf"

line_number=12
spaces="        "
# # Durchlaufe alle .pem-Dateien im Verzeichnis
for cert in $(/usr/bin/find . -path **/auth/TLS.pem)
do
    # Erstelle einen Fingerabdruck für jede .pem-Datei
    fingerprint=$(openssl x509 -in "$cert" -noout -fingerprint -sha1 | sed 's/SHA1 Fingerprint=//')
    # Füge den Fingerabdruck zur map-Direktive hinzu
    sed -i "${line_number}i${spaces}${fingerprint} 0;" "$nginx_conf"
    ((line_number++))
done