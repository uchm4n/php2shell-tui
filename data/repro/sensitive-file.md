curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' '{url}/{path}'
# a 200 with a non-zero size means the file is public

curl -sS '{url}/{path}' | head -20
# the contents themselves
