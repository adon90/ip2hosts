if [ "$#" -ne 1 ]; then
    echo "ip2hosts <ip>"
	exit 1
fi

ip2hosts() { 

        rm /tmp/domains.txt 2>/dev/null
        curl -ks https://freeapi.robtex.com/ipquery/$1 | grep -Po "(?<=\"o\":).*?(?=,)" | sed 's/\"//g' >> /tmp/domains.txt
        curl -s -A "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" "https://api.hackertarget.com/reverseiplookup/?q=$1" >> /tmp/domains.txt
        echo "" >> /tmp/domains.txt
        curl "http://www.virustotal.com/vtapi/v2/ip-address/report?ip=$1&apikey=3c052e9a7339f3a73f00bd67baea747e47f59ee6c1596e59590fd953d00ce519" -s | grep -Po "(?<=ho>
        dig +short -x $1 2>&1 | grep -v "connection timed out" >> /tmp/domains.txt
        curl -ks "https://www.bing.com/search?q=ip%3a$1" | grep -Po "(?<=<a href=\").*?(?= h=)" | grep -Po "(?<=://).*?(?=/)" | egrep -v "microsoft|bing|pointdecontact>
        nmap -p443 -Pn --script ssl-cert $1 | grep Subject | grep -Po "(?<=commonName=).*?(?=/)" | tr '[:upper:]' '[:lower:]' >> /tmp/domains.txt
        sed -i 's/\.$//g' /tmp/domains.txt
        curl -X POST -F "remoteAddress=$1"  http://domains.yougetsignal.com/domains.php -s | /usr/bin/perl -p | grep -Poz "(?s)\[.*\]" | cat -v | grep -Po "(?<=\").+(?>
        #curl -i -s -k  -X 'POST' -F "theinput=$1" -F "thetest=reverseiplookup" -F "name_of_nonce_field=23gk"    'https://hackertarget.com/reverse-ip-lookup/' | grep ->
        curl -m 3 -ks "https://www.threatcrowd.org/graphHtml.php?ip=$1" | grep -Po "(?<=id: ').*?(?=')" | grep -v  ^[0-9] | grep -v @ >> /tmp/domains.txt
        curl -s -m 3  "https://www.pagesinventory.com/ip/$1" | grep -Po "(?<=<a href=\"/domain/).*?(?=\.html)" >> /tmp/domains.txt
        curl -m 3 -A "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" -ks "https://securitytrails.com/list/ip/$1" | grep -Po "(?<=/dns\">).*?(?=<>
        sort -u /tmp/domains.txt



 }

ip2hosts $1
