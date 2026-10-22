curl -sSI {url}/ | grep -iE 'x-powered-by|generator|link:.*wp-|x-generator'
# look for framework and CMS fingerprints

curl -sS {url}/wp-includes/version.php | head -5
# WordPress exposes its version here
