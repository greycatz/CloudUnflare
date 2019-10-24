#!/bin/bash
# CloudUnflare

CompleteDNS_Login='email@mail.com|password'

if [[ -z $(command -v dig) ]]; then
	echo " ERROR: \"dig\" command not found"
	exit
elif [[ -z $(command -v curl) ]]; then
	echo " ERROR: \"curl\" command not found"
	exit
elif [[ -z $(command -v whois) ]]; then
	echo " ERROR: \"whois\" command not found"
	exit
fi

echo '       __                          '
echo '    __(  )_       CLOUDFLARE       '
echo ' __(       )_   RECONNAISSANCE     '
echo '(____________)__ _  V 0.2          '
echo ' _   _ _ __  / _| | __ _ _ __ ___  '
echo '| | | | `_ \| |_| |/ _` | `__/ _ \ '
echo '| |_| | | | |  _| | (_| | | |  __/ '
echo ' \__,_|_| |_|_| |_|\__,_|_|  \___| '
echo ''

if [[ -f cuf-domain.tmp ]]; then
	rm cuf-domain.tmp
elif [[ -f cuf-ipaddr.tmp ]]; then
	rm cuf-ipaddr.tmp
fi

echo " Input domain name"
echo " Example: google.com"
echo -ne " >> "
read DOMAIN
echo ''

if [[ -z $(dig +short ${DOMAIN}) ]]; then
	if [[ -z $(whois ${DOMAIN} | grep -i 'Domain Name:') ]]; then
		echo " ERROR: Domain not found"
		exit
	fi
fi

function Dig() {
	D=$1
	echo " INFO: Checking ${D}"
	for DMN in $(dig +short ${D} | grep '[.]'$ | sed 's/[.]$//g' | sort -V | uniq)
	do
		echo "   + CNAME: ${DMN}"
	done
	for IP in $(dig +short ${D} | grep [0-9]$ | sort -V | uniq)
	do
		VENDOR=$(curl -s "https://rdap.arin.net/registry/ip/${IP}" -H 'User-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 KHTML, like Gecko) Chrome/77.0.3865.120 Mobile Safari/537.36' --compressed | sed 's/",/\n/g' | grep '"name"' | sed 's/://g' | sed 's/"//g' | awk '{print $2}')
		echo "   + ${IP} [${VENDOR}]"
	done
}

Dig ${DOMAIN}

i=0
c=0
max=$(cat `dirname $(realpath $0)`/subdomains.txt | wc -l)
for SUBD in $(cat `dirname $(realpath $0)`/subdomains.txt)
do
	((i++))
	SUBDOMAIN=${SUBD}.${DOMAIN}
	if [[ ! -z $(dig +short ${SUBDOMAIN}) ]]; then
		Dig ${SUBDOMAIN}
	else
		((c++))
		if [[ $(expr $c % 20) -eq 0 ]]; then
			echo " INFO: Subdomain enumeration progress [${i}/${max}]"
		fi
	fi
done

function CompleteDNS() {
	DMN=${1}
	CRE=${2}
	EMAIL=$(echo ${CRE} | awk -F '|' '{print $1}')
	PASS=$(echo ${CRE} | awk -F '|' '{print $2}')
	TOKEN=$(curl -s --cookie-jar cookie.txt https://completedns.com/login | grep '_csrf_token' | sed 's/value="/\nToken /g' | grep ^Token | sed 's/"//g' | awk '{print $2}')
	if [[ ! -z $(curl -skL --cookie cookie.txt --cookie-jar cookie.txt 'https://completedns.com/login_check' --data "_csrf_token=${TOKEN}&_username=${EMAIL}&_password=${PASS}&submitButton=" | grep 'Invalid credentials.') ]]; then
		echo " ERROR: CompleteDNS cannot login"
		return 1
	fi
	if [[ -f completedns.tmp ]]; then
		rm completedns.tmp
	fi
	curl -s --cookie cookie.txt https://completedns.com/dns-history/ajax/?domain=${DMN} &>> completedns.tmp
	echo " INFO: NS History by CompleteDNS.com"
	i=0
	IFS=$'\n'
	for NSROW in $(cat completedns.tmp | sed ':a;N;$!ba;s/\n/ /g' | sed 's/clearfix/\n/g' | sed 's/col-md-2/\nASULAH/g' | grep ASULAH | sed 's/  //g' | sed 's/>/ /g' | sed 's/</ /g');
	do
		((i++))
		echo "${NSROW}" | awk '{print "   + "$11"/"$10"/"$5}'
		echo "${NSROW}" | sed 's/br \//\nNSLine /g' | grep -v '"' | grep -v '/' | awk '{print "       * "$2}'
	done
	if [[ ${i} -lt 1 ]]; then
		echo "   * Empty"
	fi
	if [[ -f completedns.tmp ]]; then
		rm completedns.tmp
	elif [[ -f cookie.txt ]]; then
		rm cookie.txt
	fi
}

CompleteDNS "${DOMAIN}" "${CompleteDNS_Login}"

function ViewDNS() {
	DMN="${1}"
	if [[ -f viewdns.tmp ]]; then
		rm viewdns.tmp
	fi
	curl -s "https://viewdns.info/iphistory/?domain=${DMN}" -H 'user-agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Mobile Safari/537.36' --compressed &>> viewdns.tmp
	COUNT=$(cat viewdns.tmp | sed ':a;N;$!ba;s/\n/ /g' | sed 's/<table border="1">/\nIPHISTORY/g' | sed 's/<\/table>/\n/g' | grep ^IPHISTORY | sed 's/<tr><td>/\n/g' | sed 's/\r//' | grep ^[0-9] | sed 's/<\/td><td>/|/g' | sed 's/<\/td><td align="center">/|/g' | sed 's/<\/td><\/tr>//g' | awk -F '|' '{print "   + "$4" | "$1" | "$3"("$2")"}' | sort -V | wc -l);
	if [[ ${COUNT} -lt 1 ]]; then
		echo " ERROR: No IP History data in ViewDNS.info"
	else
		echo " INFO: IP History by ViewDNS.info"
		cat viewdns.tmp | sed ':a;N;$!ba;s/\n/ /g' | sed 's/<table border="1">/\nIPHISTORY/g' | sed 's/<\/table>/\n/g' | grep ^IPHISTORY | sed 's/<tr><td>/\n/g' | sed 's/\r//' | grep ^[0-9] | sed 's/<\/td><td>/|/g' | sed 's/<\/td><td align="center">/|/g' | sed 's/<\/td><\/tr>//g' | awk -F '|' '{print "   + "$4" | "$1" | "$3"("$2")"}' | sort -V
	fi
	rm viewdns.tmp
}

ViewDNS ${DOMAIN}
