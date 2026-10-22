curl -sS {url}/.env | head -20
# shows the raw file, including any APP_KEY / DB_PASSWORD lines

curl -sS {url}/.env | grep -iE 'APP_KEY|DB_PASSWORD|SECRET|TOKEN'
