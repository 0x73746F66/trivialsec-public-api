#!/usr/bin/env bash

set -x
digest=$1 # sha256 sha512 sha3-256 sha3-384 sha3-512 blake2b512
http_method=$2 # GET POST
path_uri=$3
json_data=$4
# base_path=https://www.trivialsec.com
# domain_url=https://api.trivialsec.com
domain_url=http://localhost:8080
# -H "Referer: ${base_path}${path_uri}"
source .env
req_date=$(TZ=UTC date +'%FT%T')

if ! [ -z "${json_data}" ]; then
    ciphertext=$(echo -ne "${http_method}\n${path_uri}\n${req_date}\n$(echo -n $json_data | openssl enc -A -base64)" | openssl dgst -${digest} -hmac "${LOCAL_API_SECRET_KEY}" | sed 's/^.*= //')
    echo -n ${json_data} | curl -s --compressed \
        --dump-header headers.log \
        -X ${http_method} \
        -H 'Content-Type: application/json' \
        -H "X-Digest: HMAC-$(printf '%s\n' $digest | awk '{ print toupper($0) }')" \
        -H "X-Signature: ${ciphertext}" \
        -H "X-ApiKey: ${LOCAL_API_KEY}" \
        -H "X-Date: ${req_date}" \
        --data @- -- ${domain_url}${path_uri}
else
    ciphertext=$(echo -ne "${http_method}\n${path_uri}\n${req_date}" | openssl dgst -${digest} -hmac "${LOCAL_API_SECRET_KEY}" | sed 's/^.*= //')
    curl -s --compressed \
        --dump-header headers.log \
        -X ${http_method} \
        -H 'Content-Type: application/json' \
        -H "X-Digest: HMAC-$(printf '%s\n' $digest | awk '{ print toupper($0) }')" \
        -H "X-Signature: ${ciphertext}" \
        -H "X-ApiKey: ${LOCAL_API_KEY}" \
        -H "X-Date: ${req_date}" \
        ${domain_url}${path_uri}
fi
