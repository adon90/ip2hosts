ip2hosts() {
    curl https://www.robtex.com/ip-lookup/$1 --silent  | grep "xsha" | grep -Po$
    curl "http://www.virustotal.com/vtapi/v2/ip-address/report?ip=$1&apikey=3c0$
    dig -x $1 +short >> /tmp/domains.txt
    shodan host $1 2>/dev/null | grep -Po "(?<=Hostnames:\s).*" | tr -d " " >> $
    for i in {0..9}; do curl "https://www.bing.com/search?q=ip%3a$1&first=$i1" $
    sort -u /tmp/domains.txt
 }

