#!/bin/bash

set -eu

AES_KEY_LENGTH=16 # 16 bytes => 128 bit AES
AES_KEY_LENGTH_HEX=32 # 16 bytes translates to 32 digits in hex
AES_IV_LENGTH=16
AES_IV_LENGTH_HEX=32

required_commands=("aws" "openssl" "base64" "jq" "cut" "sed" "od")
operation=""
kms_key_id=""
encryption_context="{}"

main() {
    check_required_commands
    parse_args "$@"

    if [ "$operation" = "encrypt" ]; then
        do_encrypt
    elif [ "$operation" = "decrypt" ]; then
        do_decrypt
    fi
}

do_encrypt() {
    log_info "Encrypting data with key $kms_key_id (${encryption_context:-empty encryption context})"
    log_debug "Generating $AES_IV_LENGTH random bytes for IV"

    # NOTE: read + subshells used there to make the script fail if
    # the commands generating the important numbers fail

    # Generate the initialization vector
    local iv_b64
    read iv_b64 < \
        <(aws kms generate-random \
            --number-of-bytes $AES_IV_LENGTH \
            --output text \
            --query Plaintext)
    local iv_hex="$(base64tohex "$iv_b64")"
    log_debug "Generated IV: hex=$iv_hex, b64=$iv_b64"

    local key_enc key_b64;
    log_debug "Generating encrypted data key"
    read key_b64 key_enc < \
        <(aws kms generate-data-key \
            --key-id "$kms_key_id" \
            --encryption-context "$encryption_context" \
            --key-spec AES_128 \
            --output text --query '[Plaintext,CiphertextBlob]')
    local key_hex="$(base64tohex "$key_b64")"
    log_debug "Generated Data Key: hex=$key_hex, b64=$key_b64, enc=$key_enc"

    # Some important sanity checks
    if [ "${#iv_hex}" != "$AES_IV_LENGTH_HEX" ]; then
        log_error "Failed to generate initialization vector for encryption (${iv_hex:-(empty)} is not a valid IV)"
        exit 3
    fi

    if [ "${#key_hex}" != "$AES_KEY_LENGTH_HEX" ]; then
        log_error "Failed to generate datakey for encryption (${key:-(empty)} is not a valid key)"
        exit 3
    fi

    # Do the encryption
    local encrypted_data
    read encrypted_data < \
        <(openssl enc -aes-128-cbc -a \
            -K "$key_hex" \
            -iv "$iv_hex"
        )
    log_debug "encrypted_data = $encrypted_data"

    # Formulate the output
    jq -n \
        --arg EncryptedData "$encrypted_data" \
        --arg EncryptedDataKey "$key_enc" \
        --arg EncryptionContext "$encryption_context" \
        --arg Iv "$iv_hex" \
            '{ EncryptedData: $EncryptedData,
               EncryptedDataKey: $EncryptedDataKey,
               EncryptionContext: $EncryptionContext | fromjson,
               Iv: $Iv }'

}

do_decrypt() {
    # Extract the details from input
    local parsed_variables="$(jq -r '@sh "
        local encrypted_data=\(.EncryptedData)
        local key_enc=\(.EncryptedDataKey)
        local encryption_context=\(.EncryptionContext | tojson)
        local iv_hex=\(.Iv)
    "')"

    if [ -z "$parsed_variables" ]; then
        log_error "Failed to parse input from stdin"
        exit 5
    fi

    eval "$parsed_variables"

    log_debug "data = $encrypted_data"
    log_debug "key = $key_enc"
    log_debug "ctx = $encryption_context"
    log_debug "iv = $iv_hex"

    # Decrypt the data key
    local key_b64
    log_debug "Decrypting encrypted datakey"
    read key_b64 < \
        <(echo "$key_enc" | base64 -d | aws kms decrypt --encryption-context "$encryption_context" --ciphertext-blob fileb:///dev/stdin --output text --query Plaintext)
    local key_hex="$(base64tohex "$key_b64")"
    log_debug "Decrypted Data Key: hex=$key_hex, b64=$key_b64, enc=$key_enc"

    # Decrypt!
    openssl enc -aes-128-cbc -d -a \
        -K "$key_hex" \
        -iv "$iv_hex" <<< "$encrypted_data"
}

# Helper to turn short (<= 16 bytes) of base64 encoded data into hex strings
base64tohex() {
    (base64 -d | od -t x1 | cut -s -d " " -f 2- | sed "s/ //g") <<< "$1"
}

# Check that required apps can be found from the path
check_required_commands() {
    for cmd in ${required_commands[@]}; do
        if ! which $cmd > /dev/null 2>&1; then
            log_error "$cmd is required but not found from PATH"
            exit 1
        fi
    done
}

# Parses the arguments to figure out what should be done
parse_args() {
    operation="${1:-}";

    while [ $# -gt 1 ]; do
        shift

        case $1 in
        -k|--kms-key-id)
            kms_key_id="$2"; shift
        ;;
        -e|--encryption-context)
            encryption_context="$2"; shift
        ;;
        esac

    done

    if [ -z "$operation" ]; then
        exit_arg_failure "Operation missing"
    fi

    if [ "$operation" != "decrypt" ] && [ "$operation" != "encrypt" ]; then
        exit_arg_failure "Invalid operation: $operation"
    fi

    if [ "$operation" == "encrypt" ]; then
        if [ -z "$kms_key_id" ]; then
            exit_arg_failure "encrypt requires -k or --kms-key-id argument"
        fi
    fi

    if [ -n "$encryption_context" ]; then
        local parsed_ctx
        read parsed_ctx < <(echo "$encryption_context" | jq .)

        if [ -z "$parsed_ctx" ]; then
            exit_arg_failure "failed to parse the provided encryption context (must be valid JSON)"
        fi
    fi
}

exit_arg_failure() {
    log_error "$@"
    usage
    exit 2
}

# Helpers for logging messages
log_msg() {
    local level="$1"; shift
    echo "[$(date -Iseconds)] $level: $@" >&2
}
log_error() { log_msg "ERROR" "$@"; }
log_warn() { log_msg "WARNING" "$@"; }
log_info() { log_msg "INFO" "$@"; }
log_debug() {
    if [ -n "${DEBUG:-}" ]; then
        log_msg "DEBUG" "$@"
    fi
}

usage() {
    log_info "Usage:"
    log_info "  $0 encrypt --kms-key-id <uuid|arn|alias|alias_arn> [--encryption-context KeyName1=1,KeyName2=2]"
    log_info "  $0 decrypt [--encryption-context KeyName1=1,KeyName2=2]"
}

main "$@"
