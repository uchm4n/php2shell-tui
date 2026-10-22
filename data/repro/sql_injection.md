curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' '{url}'
# baseline

curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' '{url}&q=%27'
# the quote changes the response, which means the parameter reaches the database
