#!/bin/bash

# Generates example scan report for a given target

REPORT_FILE="report.txt"


#NEW - run_scan function added to run nmap scan and print results (caputred in main())
#-sV used to detect service info for Strategy B below
#--script vuln to run every NSE script in the "vuln" section
#$1 = target IP or host
run_scan() {
    local target="$1"
    nmap -sV --script vuln "$target"
}

#nvd lookup settings
MAX_NVD_QUERIES=2
nvd_query_count=0

#query nvd rest api for CVEs matching product/version. prints summary
#added rate limit safeguard to stop queries once cap is hit
query_nvd() {

    local product="$1"
    local version="$2"
    local results_limit=3
 
    if [ "$nvd_query_count" -ge "$MAX_NVD_QUERIES" ]; then
        echo "  [i] Skipping NVD query for $product $version (MAX_NVD_QUERIES=$MAX_NVD_QUERIES reached)."
        return
    fi
 
    # Sleep before every query after the first, to stay under NVD's rate limit
    if [ "$nvd_query_count" -gt 0 ]; then
        sleep 6
    fi
    nvd_query_count=$((nvd_query_count + 1))
 
    echo
    echo "Querying NVD for vulnerabilities in: $product $version..."
 
    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')
 
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"
 
    local vulnerabilities_json
    vulnerabilities_json=$(curl -s "$nvd_api_url")
 
    if [[ -z "$vulnerabilities_json" ]]; then
        echo "  [!] Error: Failed to fetch data from NVD. The API might be down or unreachable."
        return
    fi
    if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null 2>&1; then
        echo "  [!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message')"
        return
    fi
    if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null 2>&1; then
        echo "  [+] No vulnerabilities found in NVD for this keyword search."
        return
    fi
 
    echo "$vulnerabilities_json" | jq -r \
        '.vulnerabilities[] |
        "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"'


}



write_header() {
  
echo "-----------------------------------"
echo " Network Security Scan Report "
echo ""
echo "Target IP Address: $target"
echo ""
}

#$1 = full nmap scan results from run_scan
# Open Ports and Services
write_ports_section() {
  local scan_results="$1"

echo "-----------------------------------"
echo "Open Ports and Detected Services"
#prefilters used in grep
echo "$scan_results" | grep -E "^[0-9]+/tcp.*open"
echo "" 
}

#$1 = full nmap scan results from run_scan
# Vulnerabilities
write_vulns_section() {
echo "-------------------------------------------"
echo " Potential Vulnerabilities Identified "
echo ""

# Strategy A: grep for NSE "vulnerable" findings
echo "[NSE Script Findings]"
local nse_hits
nse_hits=$(echo "$scan_results" | grep "VULNERABLE")
if [ -n "$nse_hits" ]; then
  echo "$nse_hits"
  else
  echo "No NSE 'VULNERABLE' flags found."
fi
echo ""

# Strategy B: version checking against open port lines
# based on example code provided in canvas
echo "[Version-Based Checks]"
echo "$scan_results" | grep -E "^[0-9]+/tcp.*open" | while read -r line; do

# extracting port, service name, version info column
local port service version_info
port=$(echo "$line" | awk '{print $1}')
service=$(echo "$line" | awk '{print $3}')
version_info=$(echo "$line" | awk '{$1="";$2="";$3="";print}' | sed 's/^ *//')

# parse product name and version number
local product="" version=""
if [[ "$version_info" =~ ^([A-Za-z][A-Za-z0-9._+-]*(\ [A-Za-z][A-Za-z0-9._+-]*)?)\ ([0-9][A-Za-z0-9._+-]*) ]]; then
  product="${BASH_REMATCH[1]}"
  version="${BASH_REMATCH[3]}"
fi


  case "$line" in
    *"vsftpd 2.3.4"*)
      echo "Outdated FTP - vsftpd 2.3.4 has a known critical backdoor (CVE-2011-2523)"
      ;;
    *"Apache httpd 2.4.49"*)
      echo "Outdated Web Server - Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773)"
      ;;
    *"OpenSSH 4."*|*"OpenSSH 5."*)
      echo "Weak SSH - Outdated OpenSSH version detected, upgrade recommended"
      ;;
    *"Apache httpd 2.2"*)
      echo "Outdated Web Server - Apache 2.2.x is end-of-life, upgrade recommended"
      ;;
    
  esac

  # if product/version parsed, query nvd
  if [ -n "$product" ] && [ -n "$version" ]; then
    echo "Port $port ($service): detected $product $version"
    query_nvd "$product" "$version"
  fi

done
echo ""

}

# Recommendations
write_recs_section() {
echo "--------------------------------------" 
echo " Recommendations for Remediation " 
echo "1) Update all software to the latest versions." 
echo "2) Change default credentials." 
echo "3) Implement a firewall." 
echo "" 
}

# footer
write_footer() {
echo "============================================"
echo "END OF REPORT - Generated on: $(date)"
}

# main script: validation control and report generation

main(){
  # input validation: requires one argument
  if [ "$#" -ne 1 ];
    then
    echo "Usage: $0 <target_ip_or_host>" >&2
    exit 1
  fi
  
  local target="$1"


#added to run the scan once and reuse results for both ports and vulns section
  echo "Running nmap scan against $target ..."
  local scan_results
  scan_results=$(run_scan "$target")

# calling each section function in order
# using > for header to create/overwrite. >> to append remaining sections
  write_header "$target" > "$REPORT_FILE"
  write_ports_section "$scan_results" >> "$REPORT_FILE"
  write_vulns_section "$scan_results" >> "$REPORT_FILE"
  write_recs_section >> "$REPORT_FILE"
  write_footer >> "$REPORT_FILE"

  echo "Report generated: $REPORT_FILE"

}

# calling script after all functions are defined before execution
main "$@"