# Run only against an authorized target with a matching verified profile.
bin/php2shell-tui scan --config <authorized-target>.yaml --no-tui --format json --verify --yes

# The proof writes a short relative file and fetches the candidate paths.
# If it succeeds, remove that proof file from the target working directory.
