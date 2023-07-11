#!/bin/bash
# Created By shaharia
# [Support Me And join Contributor:]
######################################################################
# These tools are still in development,                              #
# if there are any problems with these tools please let me know.     #
######################################################################

# Favorite Colors
BK=$(tput setaf 0) # Black
RD=$(tput setaf 1) # Red
GR=$(tput setaf 2) # Green
YW=$(tput setaf 3) # Yellow
BG=$(tput setab 4) # Background Color
PP=$(tput setaf 5) # Purple
CY=$(tput setaf 6) # Cyan
WH=$(tput setaf 7) # White
NT=$(tput sgr0)    # Neutral
BD=$(tput bold)    # Bold
AB=$(tput setaf 8) # Abuabu

agent='User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0'
ver='0.0.1'
IFS=$'\n'
verbose=0
GitHubApi=$'Your_Github_Api'
linee=".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)"
_start=1
_end=100

total_subdomain_count=0

function count_subdomains {
    file="$1"
    count=$(wc -l <"$file")
    echo "$count"
}

function exec_Subdomains {
    subdomain_count=0

    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}Github${GR})"
    github-subs -d "$url" -api "$GitHubApi" >"$outfile/subdo/github.txtls"
    subdomain_count=$(count_subdomains "$outfile/subdo/github.txtls")
    total_subdomain_count=$((total_subdomain_count + subdomain_count))
    echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in Github: $subdomain_count${NT}"

    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}RapidDNS${GR})"
    curl -s "https://rapiddns.io/subdomain/$url?full=1#result" |
        grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" |
        grep ".$url" | sort -u >"$outfile/subdo/rapiddns.txtls"
    subdomain_count=$(count_subdomains "$outfile/subdo/rapiddns.txtls")
    total_subdomain_count=$((total_subdomain_count + subdomain_count))
    echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in RapidDNS: $subdomain_count${NT}"

    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}BufferOver${GR})"
    curl -s "https://tls.bufferover.run/dns?q=.$url" -H 'x-api-key: YourBufferOverApi'|
        grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" |
        grep ".$url" | sort -u >"$outfile/subdo/bufferover.txtls"
    subdomain_count=$(count_subdomains "$outfile/subdo/bufferover.txtls")
    total_subdomain_count=$((total_subdomain_count + subdomain_count))
    echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in BufferOver: $subdomain_count${NT}"


    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}CertSpotter${GR})"
    subdomain_count=0
    while read -r dns_name; do
        if [[ $dns_name == *".$url" ]]; then
            subdomain=$(echo "$dns_name" | sed 's/^\*\.\(.*\)$/\1/')  # Remove leading "*."
            echo "$subdomain" >> "$outfile/subdo/certspotter.txtls"
            ((subdomain_count++))
        fi
    done < <(curl -s "https://api.certspotter.com/v1/issuances?domain=$url&expand=dns_names&expand=issuer&expand=cert" | jq -r '.[].dns_names[]')

    total_subdomain_count=$((total_subdomain_count + subdomain_count))
    echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in CertSpotter: $subdomain_count${NT}"


    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}crt.sh${GR})"
    crtsh_response=$(curl -s "https://crt.sh/?q=%25.$url&output=json")
    if [[ $? -eq 0 ]]; then
        subdomains=$(echo "$crtsh_response" | jq -r '.[].name_value' | grep -E "(^|\.)$url$" | sed 's/^\.//')
        if [[ -n "$subdomains" ]]; then
            echo "$subdomains" | sort -u >"$outfile/subdo/crtsh.txtls"
            subdomain_count=$(count_subdomains "$outfile/subdo/crtsh.txtls")
            total_subdomain_count=$((total_subdomain_count + subdomain_count))
            echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in crt.sh: $subdomain_count${NT}"
        fi
    fi


    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}urlscan${GR})"
    urlscan_response=$(curl -s "https://urlscan.io/api/v1/search/?q=domain:$url")
    if [[ $? -eq 0 ]]; then
        subdomains=$(echo "$urlscan_response" | jq -r '.results[].page.domain' | grep -E "(^|\.)$url$")
        if [[ -n "$subdomains" ]]; then
            echo "$subdomains" | sort -u >"$outfile/subdo/urlscan.txtls"
            subdomain_count=$(count_subdomains "$outfile/subdo/urlscan.txtls")
            total_subdomain_count=$((total_subdomain_count + subdomain_count))
            echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in urlscan: $subdomain_count${NT}"
        fi
    fi

    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}alienvault${GR})"
    alienvault_response=$(curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$url/passive_dns")
    if [[ $? -eq 0 ]]; then
        subdomains=$(echo "$alienvault_response" | jq -r '.passive_dns[].hostname' | grep -E "(^|\.)$url$")
        if [[ -n "$subdomains" ]]; then
            echo "$subdomains" | sort -u >"$outfile/subdo/alienvault.txtls"
            subdomain_count=$(count_subdomains "$outfile/subdo/alienvault.txtls")
            total_subdomain_count=$((total_subdomain_count + subdomain_count))
            echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in alienvault: $subdomain_count${NT}"
        fi
    fi

    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}securitytrails${GR})"
    securitytrails_response=$(curl --request GET \
         --url "https://api.securitytrails.com/v1/domain/$url/subdomains?children_only=false&include_inactive=true" \
         --header 'APIKEY: YourSecurityTrailsApi' \
         --header 'accept: application/json')
    if [[ $? -eq 0 ]]; then
        subdomains=$(echo "$securitytrails_response" | jq -r '.subdomains[]?')
        if [[ -n "$subdomains" ]]; then
            filepath="$outfile/subdo/securitytrails.txtls"
            while IFS= read -r subdomain; do
                echo "$subdomain.$url"
            done <<< "$subdomains" >"$filepath"
            subdomain_count=$(count_subdomains "$filepath")
            total_subdomain_count=$((total_subdomain_count + subdomain_count))
            echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in securitytrails: $subdomain_count${NT}"
        else
            echo -e "${NT}[${RD}~${NT}]${GR} ${CY}No subdomains found.${NT}"
        fi
    fi

    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}virustotal${GR})"
    virustotal_response=$(curl -s -H "x-apikey: YourVirusTotalAPI" "https://www.virustotal.com/api/v3/domains/$url/subdomains")
    if [[ $? -eq 0 ]]; then
        subdomains=$(echo "$virustotal_response" | jq -r '.data[].id' | grep -E "(^|\.)$url$")
        if [[ -n "$subdomains" ]]; then
            echo "$subdomains" | sed "s/\.$url$//" | sort -u >"$outfile/subdo/virustotal.txtls"
            subdomain_count=$(count_subdomains "$outfile/subdo/virustotal.txtls")
            total_subdomain_count=$((total_subdomain_count + subdomain_count))
            echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in virustotal: $subdomain_count${NT}"
        fi
    fi
    
    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}assetfinder${GR})"
    assetfinder $url   >> $outfile/subdo/assetfinder.txtls
    subdomain_count=$(count_subdomains "$outfile/subdo/assetfinder.txtls")
    total_subdomain_count=$((total_subdomain_count + subdomain_count))
    echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in assetfinder: $subdomain_count${NT}"
    
    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}subfinder${GR})"
    subfinder -d $url -silent -all   >> $outfile/subdo/subfinder.txtls
    subfinder -d $url -silent -all -active  >> $outfile/subdo/subfinder.txtls
    subdomain_count=$(count_subdomains "$outfile/subdo/subfinder.txtls")
    total_subdomain_count=$((total_subdomain_count + subdomain_count))
    echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in subfinder: $subdomain_count${NT}"
    
    echo -e "${NT}[${RD}~${NT}]${GR} Searching now in (${NT}amass${GR})"
    amass enum -d $url -passive  >> $outfile/subdo/amass.txtls
    subdomain_count=$(count_subdomains "$outfile/subdo/amass.txtls")
    total_subdomain_count=$((total_subdomain_count + subdomain_count))
    echo -e "${NT}[${RD}~${NT}]${GR} ${CY}Subdomains found in amass: $subdomain_count${NT}"
}


url=$1
outfile="output/$url"
mkdir -p "$outfile/subdo"

exec_Subdomains

# Combine all subdomain files into a single file
cat "$outfile/subdo/"*".txtls" | sort -u >"$outfile/all_subdomains.txt"

# Remove individual subdomain files except all_subdomains.txt
rm -f "$outfile/subdo/"*[!.]txtls

echo -e "${NT}[${RD}~${NT}]${GR} Subdomain enumeration completed. Results are stored in '$outfile/all_subdomains.txt'"

echo -e "${NT}[${RD}~${NT}]${GR} ${BD}${CY}Total Subdomains found: $total_subdomain_count${NT}"
