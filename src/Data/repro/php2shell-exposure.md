curl -sSI {url} | grep -iE 'x-powered-by|server'

curl -sS {url}/phpinfo.php | grep -iE 'PHP Version|Server API|session.upload_progress|session.use_strict_mode|memory_limit|post_max_size|display_errors'

bin/php2shell-tui scan --config <target>.yaml --no-tui --format json --verify --php-version <x.y.z> --arch <amd64|aarch64> --workers <target-maxrequestworkers>
