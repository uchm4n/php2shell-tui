nc -zv {host} 3306
# confirms the service answers from outside your perimeter

for p in 21 22 25 3306 5432 6379 8080 8443 27017; do nc -zv -w 1 {host} $p; done
# sweeps the rest of the list in src/Data/open-ports.txt
