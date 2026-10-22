echo | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null | openssl x509 -noout -dates
# shows the certificate validity window

echo | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName
# shows the names the certificate is issued for
