#!/usr/bin/env bats

setup_file() {
    load 'test_helper'
    wait_for_service
    wait_for_tokenreview
}

setup() {
    load 'test_helper'
}

@test "metrics endpoint returns prometheus metrics" {
    local result
    result=$(kexec curl -s "${SERVICE_URL}/metrics")

    echo "# Response (first 10 lines): $(echo "$result" | head -10)"

    # Should contain kfa_ prefixed metrics
    echo "$result" | grep -q "kfa_http_requests_total"
    echo "$result" | grep -q "kfa_server_info"

    # server_info should have the version label set to 1
    echo "$result" | grep -qE 'kfa_server_info\{version="[^"]+"\} 1'
}

@test "health endpoint returns ok" {
    local result
    result=$(kexec curl -s "${SERVICE_URL}/health")

    echo "# Response: $result"

    local status
    status=$(echo "$result" | jq -r '.status')
    [[ "$status" == "ok" ]]
}

@test "clusters endpoint lists configured clusters" {
    local result
    result=$(kexec curl -s "${SERVICE_URL}/clusters")

    echo "# Response: $result"

    local names
    names=$(echo "$result" | jq -r '.clusters[].name')
    echo "$names" | grep -q "$CLUSTER_NAME"
}

@test "TokenReview authenticates valid token" {
    local token
    token=$(get_token)

    local result
    result=$(token_review "$token")

    echo "# Response: $result"

    # Check authenticated
    local authenticated
    authenticated=$(echo "$result" | jq -r '.status.authenticated')
    [[ "$authenticated" == "true" ]]

    # Check username starts with system:serviceaccount:
    local username
    username=$(echo "$result" | jq -r '.status.user.username')
    [[ "$username" == system:serviceaccount:* ]]

    # Check apiVersion and kind
    local apiVersion kind
    apiVersion=$(echo "$result" | jq -r '.apiVersion')
    kind=$(echo "$result" | jq -r '.kind')
    [[ "$apiVersion" == "authentication.k8s.io/v1" ]]
    [[ "$kind" == "TokenReview" ]]

    # Check cluster-name in extra field
    local clusterExtra
    clusterExtra=$(echo "$result" | jq -r '.status.user.extra["authentication.kubernetes.io/cluster-name"][0]')
    [[ "$clusterExtra" == "$CLUSTER_NAME" ]]
}

@test "TokenReview works with separate caller and review tokens" {
    # Caller authenticates with their default SA token (Authorization header),
    # and reviews a different token (the projected one in request body)
    local caller_token
    caller_token=$(get_caller_token)

    local review_token
    review_token=$(get_token)

    local result
    result=$(kexec curl -s -X POST "${SERVICE_URL}/apis/authentication.k8s.io/v1/tokenreviews" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${caller_token}" \
        -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"${review_token}\"}}")

    echo "# Response: $result"

    local authenticated
    authenticated=$(echo "$result" | jq -r '.status.authenticated')
    [[ "$authenticated" == "true" ]]

    local username
    username=$(echo "$result" | jq -r '.status.user.username')
    [[ "$username" == system:serviceaccount:* ]]
}

@test "TokenReview authenticates cluster-b token" {
    # Caller: whitelisted SA from cluster-a (Authorization header)
    # Payload: SA token from cluster-b (TokenReview body)
    local caller_token
    caller_token=$(get_caller_token)

    local review_token
    review_token=$(get_cluster_b_token)

    local result
    result=$(kexec curl -s -X POST "${SERVICE_URL}/apis/authentication.k8s.io/v1/tokenreviews" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${caller_token}" \
        -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"${review_token}\"}}")

    echo "# Response: $result"

    local authenticated
    authenticated=$(echo "$result" | jq -r '.status.authenticated')
    [[ "$authenticated" == "true" ]]

    # Verify identity is from cluster-b's reader SA
    local username
    username=$(echo "$result" | jq -r '.status.user.username')
    [[ "$username" == "system:serviceaccount:kube-federated-auth:kube-federated-auth-reader" ]]

    # Verify cluster-name extra field says cluster-b
    local clusterExtra
    clusterExtra=$(echo "$result" | jq -r '.status.user.extra["authentication.kubernetes.io/cluster-name"][0]')
    [[ "$clusterExtra" == "cluster-b" ]]
}

@test "TokenReview authenticates legacy SA token (kubernetes.io/service-account-token)" {
    # Legacy Secret-based SA tokens have issuer "kubernetes/serviceaccount"
    # instead of the OIDC issuer. They should still be verifiable via JWKS.
    local token
    token=$(get_legacy_sa_token test-client)

    echo "# Token length: ${#token}"

    local result
    result=$(token_review "$token")

    echo "# Response: $result"

    local authenticated
    authenticated=$(echo "$result" | jq -r '.status.authenticated')
    [[ "$authenticated" == "true" ]]

    local username
    username=$(echo "$result" | jq -r '.status.user.username')
    [[ "$username" == "system:serviceaccount:${NAMESPACE}:test-client" ]]
}

@test "TokenReview rejects invalid token" {
    local result
    result=$(token_review "invalid.token.here")

    echo "# Response: $result"

    # authenticated should be false or absent (null)
    local authenticated
    authenticated=$(echo "$result" | jq -r '.status.authenticated')
    [[ "$authenticated" == "false" ]] || [[ "$authenticated" == "null" ]]

    local error
    error=$(echo "$result" | jq -r '.status.error')
    [[ -n "$error" ]]
    [[ "$error" != "null" ]]
}

@test "TokenReview rejects unauthorized caller with 403" {
    # Use a valid token from a SA that is NOT in authorized_clients
    local caller_token
    caller_token=$(get_unauthorized_caller_token)

    local review_token
    review_token=$(get_token)

    local http_code body
    body=$(kexec curl -s -w '\n%{http_code}' -X POST \
        "${SERVICE_URL}/apis/authentication.k8s.io/v1/tokenreviews" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${caller_token}" \
        -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"${review_token}\"}}")

    http_code=$(echo "$body" | tail -1)
    body=$(echo "$body" | sed '$d')

    echo "# HTTP status: $http_code"
    echo "# Response: $body"

    [[ "$http_code" == "403" ]]

    local error
    error=$(echo "$body" | jq -r '.status.error')
    [[ "$error" == "caller is not authorized" ]]
}

@test "TokenReview rejects request without Authorization header" {
    # Send a TokenReview without caller auth — should get 401
    local http_code
    http_code=$(kexec curl -s -o /dev/null -w '%{http_code}' -X POST \
        "${SERVICE_URL}/apis/authentication.k8s.io/v1/tokenreviews" \
        -H "Content-Type: application/json" \
        -d '{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"some-token"}}')

    echo "# HTTP status: $http_code"
    [[ "$http_code" == "401" ]]
}

@test "TokenReview forwards spec.audiences to the remote cluster" {
    # Separate tokens per request so the cache does not affect this test
    local token_match token_mismatch
    token_match=$(get_cluster_b_token_aud "service-a")
    token_mismatch=$(get_cluster_b_token_aud "service-a")

    # Matching audience: authenticated, status.audiences echoes the match
    local result
    result=$(token_review_aud "$token_match" '["service-a"]')
    echo "# Matching audience response: $result"
    [[ "$(echo "$result" | jq -r '.status.authenticated')" == "true" ]]
    [[ "$(echo "$result" | jq -c '.status.audiences')" == '["service-a"]' ]]

    # Mismatched audience: not authenticated (false or omitted)
    result=$(token_review_aud "$token_mismatch" '["service-b"]')
    echo "# Mismatched audience response: $result"
    [[ "$(echo "$result" | jq -r '.status.authenticated == true')" == "false" ]]
}
