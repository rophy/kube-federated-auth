#!/usr/bin/env bats

# Cache e2e tests
# These tests temporarily switch log_level to DEBUG to verify cache behavior,
# then restore the original ConfigMap in teardown.

setup_file() {
    load 'test_helper'
    wait_for_service
    wait_for_tokenreview
    save_configmap
    patch_configmap_field "log_level: DEBUG"
}

teardown_file() {
    load 'test_helper'
    restore_configmap
}

setup() {
    load 'test_helper'
}

@test "TokenReview cache hit on repeated token" {
    local token
    token=$(get_token)

    # Record timestamp before requests
    local since
    since=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # First request — should be a cache miss (forwarded to upstream)
    local result1
    result1=$(token_review "$token")
    echo "# First response: $result1"

    local auth1
    auth1=$(echo "$result1" | jq -r '.status.authenticated')
    [[ "$auth1" == "true" ]]

    # Second request with same token — should be a cache hit
    local result2
    result2=$(token_review "$token")
    echo "# Second response: $result2"

    local auth2
    auth2=$(echo "$result2" | jq -r '.status.authenticated')
    [[ "$auth2" == "true" ]]

    # Allow logs to flush
    sleep 1

    # Check server logs for cache hit
    local logs
    logs=$(server_logs_since "$since")
    echo "# Server logs: $logs"

    echo "$logs" | grep -q "cache=hit"
}
