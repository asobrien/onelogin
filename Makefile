
lint:
	golint

fmt:
	gofmt -l -w .

test:
	go test

test-integration:
	@go test -tags=integration \
		-client-id="${ONELOGIN_AUTH_CLIENT_ID}" \
		-client-secret="${ONELOGIN_AUTH_CLIENT_SECRET}" \
		-shard="us" \
		-team="metagiphy-dev" \
		-username="${ONELOGIN_USER_EMAIL}" \
		-password="${ONELOGIN_USER_PASSWORD}" \
		-otp-url="${ONELOGIN_USER_OTP}" \
		-app-id=838187

test-uat:
	@go run -tags=uat uat_test/*.go \
		-client-id="${ONELOGIN_AUTH_CLIENT_ID}" \
		-client-secret="${ONELOGIN_AUTH_CLIENT_SECRET}" \
		-shard="us" \
		-team="metagiphy-dev"

proxy-server:
	@go run cmd/saml-proxy-server/*.go \
		-client-id="${ONELOGIN_AUTH_CLIENT_ID}" \
		-client-secret="${ONELOGIN_AUTH_CLIENT_SECRET}" \
		-shard="us" \
		-team="metagiphy-dev" \
		-app-id=838187
