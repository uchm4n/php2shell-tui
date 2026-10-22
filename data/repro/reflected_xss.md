curl -sS '{url}&q=php2scanmarker' | grep -o 'php2scanmarker'
# the marker comes back unencoded, so a script tag would execute
