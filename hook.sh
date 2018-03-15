#!/bin/bash
set -e

: ${SELECTEL_TOKEN?"Need to set environment variable SELECTEL_TOKEN"};

#
# Dehydrated hook script that employs curl + http API to enable dns-01 challenges with Selectel DNS
# - Will automatically identify the correct Selectel DNS zone for each domain name
# - Supports certificates with alternative names in different zones
#
# Sergey Ugdyzhekov <sergey@ugdyzhekov.org>, 2017
# https://github.com/sugdyzhekov/dehydrated-selectel-dns-hook-script
# Based on dehydrated hook.sh which was wrote by Aaron Roydhouse <aaron@roydhouse.com>
# https://github.com/whereisaaron/dehydrated-route53-hook-script
#
# Requires:
#  - dehydrated (https://github.com/lukas2511/dehydrated)
#  - openssl
#  - curl
#  - bash
#  - jq
#  - mailx
#  - sed
#  - xargs
#
# Requires Selectel DNS API token
# https://blog.selectel.ru/upravlenie-domenami-s-selectel-dns-api/
# Set SELECTEL_TOKEN environment variable
#
# Neither dehydrated nor this script needs to run as root, so don't do it!
#

#
# This hook is called once for every domain that needs to be
# validated, including any alternative names you may have listed.
#
# Creates TXT record is appropriate domain, and waits for it to sync
#
deploy_challenge() {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"
    local ZONE=$(find_zone "${DOMAIN}")
    
    if [[ -n "$ZONE" ]]; then
        echo "Creating challenge record for ${DOMAIN} in zone ${ZONE}"

        local ZONE_ID=$(curl -sS -H "X-Token: ${SELECTEL_TOKEN}" https://api.selectel.ru/domains/v1/${ZONE} | jq .id)
        local JSON='{"name": "_acme-challenge.'${DOMAIN}'", "type": "TXT", "ttl": 60, "content": "'${TOKEN_VALUE}'" }'

        curl -sS -H "Content-Type: application/json" -H "X-Token: ${SELECTEL_TOKEN}" -d "${JSON}" \
            https://api.selectel.ru/domains/v1/${ZONE_ID}/records/ >/dev/null

    else
        echo "Could not find zone for ${DOMAIN}"
        exit 1
    fi
}

#
# This hook is called after attempting to validate each domain,
# whether or not validation was successful. Here you can delete
# files or DNS records that are no longer needed.
#
# Delete TXT record from appropriate domain zone, does not wait the deletion to sync
#
clean_challenge() {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"
    local ZONE=$(find_zone "${DOMAIN}")
    
    if [[ -n "$ZONE" ]]; then
        echo "Deleting challenge record for ${DOMAIN} from zone ${ZONE}"

        local ZONE_ID=$(curl -sS -H "X-Token: ${SELECTEL_TOKEN}" https://api.selectel.ru/domains/v1/${ZONE} | jq .id)
        local RR_IDS=$(curl -sS -H "X-Token: ${SELECTEL_TOKEN}" https://api.selectel.ru/domains/v1/${ZONE_ID}/records/ | jq '.[] | select(.name | contains("_acme-challenge.")) | .id')

        for RR_ID in $RR_IDS
        do
          curl -sS -X DELETE -H "X-Token: ${SELECTEL_TOKEN}" \
              https://api.selectel.ru/domains/v1/${ZONE_ID}/records/${RR_ID}
        done
    else
        echo "Could not find zone for ${DOMAIN}"
        exit 1
    fi

    #
    # The parameters are the same as for deploy_challenge.
}

#
# This hook is called once for each certificate that has been
# produced. Here you might, for instance, copy your new certificates
# to service-specific locations and reload the service.
#
deploy_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}" TIMESTAMP="${6}"

    # NOP
}

#
# This hook is called once for each certificate that is still
# valid and therefore wasn't reissued.
#
unchanged_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"

    # NOP
}

generate_csr() {
    local DOMAIN="${1}" CERTDIR="${2}" ALTNAMES="${3}"

    # This hook is called before any certificate signing operation takes place.
    # It can be used to generate or fetch a certificate signing request with external
    # tools.
    # The output should be just the cerificate signing request formatted as PEM.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain as specified in domains.txt. This does not need to
    #   match with the domains in the CSR, it's basically just the directory name.
    # - CERTDIR
    #   Certificate output directory for this particular certificate. Can be used
    #   for storing additional files.
    # - ALTNAMES
    #   All domain names for the current certificate as specified in domains.txt.
    #   Again, this doesn't need to match with the CSR, it's just there for convenience.

    # Simple example: Look for pre-generated CSRs
    # if [ -e "${CERTDIR}/pre-generated.csr" ]; then
    #   cat "${CERTDIR}/pre-generated.csr"
    # fi
}



#
# This hook is called if the challenge response has failed, so domain
# owners can be aware and act accordingly.
#
function invalid_challenge {
    local DOMAIN="${1}" RESPONSE="${2}"

    local HOSTNAME="$(hostname)"

    # Output error to stderr
    (>&2 echo "Failed to issue SSL cert for ${DOMAIN}: ${RESPONSE}")

    # Mail error to root user
    mailx -s "Failed to issue SSL cert for ${DOMAIN} on ${HOSTNAME}" root <<-END
      Failed to issue SSL cert for ${DOMAIN} on ${HOSTNAME}

      Error from verification server:
      ${RESPONSE}
END
}

#
# Remove one level from the front of a domain name
# Returns the rest of the domain name (success), or blank if nothing left (fail)
#
function get_base_name() {
    local HOSTNAME="${1}"

    if [[ "$HOSTNAME" == *"."* ]]; then
      HOSTNAME="${HOSTNAME#*.}"
      echo "$HOSTNAME"
      return 0
    else
      echo ""
      return 1
    fi
}

#
# Find the domain zone for this domain name
# Prefers the longest match, e.g. if creating 'a.b.foo.baa.com',
# a 'foo.baa.com' zone will be preferred over a 'baa.com' zone
# Returns the zone name (success) or nothing (fail)
#
function find_zone() {
  local DOMAIN="${1}"
  local ZONELIST=$(curl -sS -H "X-Token: ${SELECTEL_TOKEN}" https://api.selectel.ru/domains/v1/ | jq .[].name | xargs echo -n)
  local TESTDOMAIN="${DOMAIN}"

  while [[ -n "$TESTDOMAIN" ]]; do
    for zone in $ZONELIST; do
      if [[ "$zone" == "$TESTDOMAIN" ]]; then
        echo "$zone"
        return 0
      fi
    done
    TESTDOMAIN=$(get_base_name "$TESTDOMAIN")
  done

  return 1
}

function startup_hook() {
  return 0
}
function exit_hook() {
  return 0
}

HANDLER="$1"; shift
if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge|deploy_cert|unchanged_cert|invalid_challenge|request_failure|generate_csr|startup_hook|exit_hook)$ ]]; then
  "$HANDLER" "$@"
fi
