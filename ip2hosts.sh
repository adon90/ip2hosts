if [ "$#" -ne 1 ]; then
    echo "ip2hosts <ip>"
	exit 1
fi

ip2hosts() { 

	ip_real=$1
	rm /tmp/domains.txt  2>/dev/null
	curl -ks https://freeapi.robtex.com/ipquery/$1 | grep -Po "(?<=\"o\":).*?(?=,)" | sed 's/\"//g' >> /tmp/domains.txt
	curl "http://www.virustotal.com/vtapi/v2/ip-address/report?ip=$1&apikey=3c052e9a7339f3a73f00bd67baea747e47f59ee6c1596e59590fd953d00ce519" -s | json_pp 2>/dev/null | grep -Po "(?<=\"hostname\" : \").*?(?=\",)" >> /tmp/domains.txt
	dig +short -x $1 >> /tmp/domains.txt
	#for i in {0..9}; do curl "https://www.bing.com/search?q=ip%3a$1&first=$i1" -s |  grep -Po "(?<=<a href=\").*?(?= h=)" | grep -Po "(?<=://).*?(?=/)" | egrep -v "microsoft|bing|pointdecontact"; done >> /tmp/domains.txt
	seq 0 9 | xargs -n1 -P4 bash -c 'i=$0; url="https://www.bing.com/search?q=ip%3a'$1'&first=${i}1"; curl -s $url | grep -Po "(?<=<a href=\").*?(?= h=)" | grep -Po "(?<=://).*?(?=/)" | egrep -v "microsoft|bing|pointdecontact"' >> /tmp/domains.txt
	nmap -Pn -p443 --script ssl-cert $1 | grep Subject | grep -Po "(?<=commonName=).*?(?=/)" | tr '[:upper:]' '[:lower:]' >> /tmp/domains.txt
	sed -i 's/\.$//g' /tmp/domains.txt
	curl -X POST -F "remoteAddress=$1"  http://domains.yougetsignal.com/domains.php -s | /usr/bin/perl -p | grep -Poz "(?s)\[.*\]" | cat -v | grep -Po "(?<=\").+(?=\")" >> /tmp/domains.txt
	curl -i -s -k  -X 'POST' -F "theinput=$1" -F "thetest=reverseiplookup" -F "name_of_nonce_field=23gk"    'https://hackertarget.com/reverse-ip-lookup/' | grep -Poz "(?s)(?<=<pre id=\"formResponse\">).*?(?=</pre>)" | grep -Piva "no records" | grep -Pa \w>> /tmp/domains.txt
	curl -i -s -k  -X 'GET' 'https://www.threatcrowd.org/graphHtml.php?ip=$1' | grep -Po "(?<=source: ').*?(?=')" | egrep -v ^[0-9] | sort -u >> /tmp/domains.txt
	sort -u /tmp/domains.txt



 }

ip2hosts $1
