#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"

curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[].ip_prefix' > "$DIR/AWS.txt"
curl -s https://www.gstatic.com/ipranges/cloud.json | jq -r '.prefixes[] | select(.ipv4Prefix != null) | .ipv4Prefix' > "$DIR/GCP.txt"
curl -s -L https://digitalocean.com/geo/google.csv | cut -d "," -f 1 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' > "$DIR/DigitalOcean.txt"
curl -s -L https://docs.oracle.com/iaas/tools/public_ip_ranges.json | jq -r '.regions.[].cidrs[].cidr' > "$DIR/Oracle.txt"
curl  -s https://api.fastly.com/public-ip-list | jq -r '.addresses[]' > "$DIR/Fastly.txt"
curl -s https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/microsoft-azure-ip-ranges.json | jq -r '.values[].properties.addressPrefixes.[]' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' > "$DIR/Azure.txt"
curl -s -L https://www.cloudflare.com/ips-v4 > "$DIR/Cloudfare.txt"
echo "" >> "$DIR/Cloudfare.txt"
curl -s -L https://geoip.linode.com | cut -d "," -f 1 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' > "$DIR/Linode.txt"

# Unir todos los .txt en uno solo
rm "$DIR/All_CIDRs.txt"
cat "$DIR/"*.txt > "$DIR/All_CIDRs.txt"
cp "$DIR/All_CIDRs.txt" "$DIR/../ips.txt"