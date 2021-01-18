#!/usr/bin/env sh

set -x
digest=$1 # sha256 sha512 sha3-256 sha3-384 sha3-512 blake2b512
http_method=$2 # GET POST
path_uri=$3
json_data=$4
base_path=https://www.trivialsec.com
#  -H "Referer: ${base_path}${path_uri}"
api_key=0cbd6369526457cebea116273ebf1fcb
api_key_secret=fi3GrjfQiGp3z0P0iFrTljRSiQTNdzR9OHhzB5zLXiA
req_date=$(TZ=UTC date +'%FT%T')

if ! [ -z "${json_data}" ]; then
    echo -n ${json_data} | curl -s --compressed \
        -X ${http_method} \
        -H 'Content-Type: application/json' \
        -H "X-Digest: HMAC-$(printf '%s\n' $digest | awk '{ print toupper($0) }')" \
        -H "X-Signature: $(echo -n "${http_method}\n${path_uri}\n${req_date}\n$(echo -n $json_data | openssl enc -base64)" | openssl dgst -${digest} -hmac "${api_key_secret}" | sed 's/^.*= //')" \
        -H "X-ApiKey: ${api_key}" \
        -H "X-Date: ${req_date}" \
        --data @- -- http://localhost:8080${path_uri}
else
    curl -s --compressed \
        -X ${http_method} \
        -H 'Content-Type: application/json' \
        -H "X-Digest: HMAC-$(printf '%s\n' $digest | awk '{ print toupper($0) }')" \
        -H "X-Signature: $(echo -n "${http_method}\n${path_uri}\n${req_date}" | openssl dgst -${digest} -hmac "${api_key_secret}" | sed 's/^.*= //')" \
        -H "X-ApiKey: ${api_key}" \
        -H "X-Date: ${req_date}" \
        http://localhost:8080${path_uri}
fi
