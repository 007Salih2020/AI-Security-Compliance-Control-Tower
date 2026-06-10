#!/bin/sh
set -eu

OUTPUT_DIR="${PROWLER_OUTPUT_DIR:-/output}"
OUTPUT_FILENAME="${PROWLER_OUTPUT_FILENAME_PREFIX:-controllens-azure-security}"

mkdir -p "${OUTPUT_DIR}"

if [ -n "${AZURE_CLIENT_ID:-}" ] && [ -n "${AZURE_CLIENT_SECRET:-}" ] && [ -n "${AZURE_TENANT_ID:-}" ]; then
  AUTH_FLAG="--sp-env-auth"
elif [ "${PROWLER_USE_AZ_CLI_AUTH:-false}" = "true" ]; then
  AUTH_FLAG="--az-cli-auth"
else
  echo "Skipping Prowler scan because Azure service principal variables are not configured."
  exit 0
fi

set -- prowler azure "${AUTH_FLAG}" \
  --output-formats json-ocsf csv \
  --output-directory "${OUTPUT_DIR}" \
  --output-filename "${OUTPUT_FILENAME}"

if [ -n "${AZURE_SUBSCRIPTION_ID:-}" ]; then
  OLD_IFS="${IFS}"
  IFS=","
  set -- "$@" --subscription-ids
  for subscription_id in ${AZURE_SUBSCRIPTION_ID}; do
    trimmed="$(echo "${subscription_id}" | xargs)"
    if [ -n "${trimmed}" ]; then
      set -- "$@" "${trimmed}"
    fi
  done
  IFS="${OLD_IFS}"
fi

exec "$@"
