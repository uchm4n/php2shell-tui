curl -sS '{url}&q=php2shell-tuimarker' | grep -o 'php2shell-tuimarker'
# the marker comes back unencoded, so a script tag would execute
