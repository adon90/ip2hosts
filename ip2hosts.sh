if [ "$#" -ne 1 ]; then
    echo "ip2hosts <ip>"
	exit 1
fi
ip2hosts() { 
	curl https://www.robtex.com/ip-lookup/$1 --silent  | grep "xsha" | grep -Po "(?<=dns-lookup/).*?(?=\">)" >> /tmp/domains.txt
	curl "http://www.virustotal.com/vtapi/v2/ip-address/report?ip=$1&apikey=3c052e9a7339f3a73f00bd67baea747e47f59ee6c1596e59590fd953d00ce519" -s | json_pp | grep -Po "(?<=\"hostname\" : \").*?(?=\",)" >> /tmp/domains.txt
	dig +short -x $1 >> /tmp/domains.txt
	shodan host $1 2>/dev/null | grep -Po "(?<=Hostnames:\s).*" | tr -d " " >> /tmp/domains.txt
	for i in {0..9}; do curl "https://www.bing.com/search?q=ip%3a$1&first=$i1" -s |  grep -Po "(?<=<a href=\").*?(?= h=)" | grep -Po "(?<=://).*?(?=/)" | egrep -v "microsoft"; done >> /tmp/domains.txt
	sort -u /tmp/domains.txt
 }

ip2hosts
