curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' '{url}/{path}'
# a 200 on a webshell filename is the tell

curl -sS '{url}/{path}' | grep -iE 'system\(|shell_exec\(|passthru\(|proc_open\(|base64_decode\('
# confirms the file actually executes shell commands
