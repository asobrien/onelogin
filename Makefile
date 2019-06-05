
lint:
	golint

fmt:
	gofmt -l -w .

test:
	go test

test-integration:
	@go test -tags=integration \
		-client_id="${ONELOGIN_AUTH_CLIENT_ID}" \
		-client_secret="${ONELOGIN_AUTH_CLIENT_SECRET}" \
		-shard="us" \
		-team="metagiphy-dev" \
		-username="${ONELOGIN_USER_EMAIL}" \
		-password="${ONELOGIN_USER_PASSWORD}" \
		-otp_url="${ONELOGIN_USER_OTP}"