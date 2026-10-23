curl -sI {url}/ | grep -iE 'x-powered-by|^server:|set-cookie'
# shows candidate signals; only PHP/PHPSESSID are PHP-specific
# X-Powered-By: Express is not PHP

ssh {host} 'php -v'
# the authoritative version, which the headers may hide

# if the headers hide PHP, check the host directly
