# Run only against an authorized target with a calibrated profile.
bin/php2shell-tui scan --config <authorized-target>.yaml --no-tui --format json --verify --php-version <x.y.z> --arch <amd64|aarch64> --workers <target-maxrequestworkers>

# The chain writes a one-character proof file. Remove it from the target working directory after the proof is fetched.
