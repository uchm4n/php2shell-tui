curl -sI {url}/ | grep -iE 'x-powered-by|^server:|set-cookie'
# lists the signals that reveal the host runs PHP

ssh {host} 'php -v'
# the authoritative version, which the headers may hide
