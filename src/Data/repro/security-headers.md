curl -sSI {url}/ | grep -iE 'strict-transport-security|content-security-policy|x-content-type-options|x-frame-options|referrer-policy'
# shows which security headers are actually sent

curl -sSI {url}/ | grep -i set-cookie
# shows the cookie flags
