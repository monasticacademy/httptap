default: run

force:

build:
	go build

clean: force
	rm -rf out

test:
	go run ./testing/run-tests --exclude '*ipv6*' '*sudo*'

run: clean
	httptap bash

install:
	go install

webui-sleep-forever: install
	httptap --webui :5000 -- sleep infinity

webui-curl-loop: install
	httptap --webui :5000 -- bash -c "while true; do echo "curling..."; curl -s https://www.example.com > out; sleep 1; done"

tcpdump-port-11223:
	sudo tcpdump -i lo 'tcp port 11223'

# Setup tests

setup-tests:
	go install

# Test cases that run in CI

test-echo: setup-tests
	httptap -- echo "hello"

# Output:
# hello

test-curl: setup-tests
	httptap -- bash -c "curl -s https://example.com > out"

# Output:
# ---> GET https://example.com/
# <--- 200 https://example.com/ (1256 bytes)

test-curl-http: setup-tests
	httptap -- bash -c "curl -s http://example.com > out"

# Output:
# ---> GET http://example.com/
# <--- 200 http://example.com/ (1256 bytes)

test-curl-monasticacademy-http: setup-tests
	httptap -- curl -Lso /dev/null http://monasticacademy.org

# Output:
# ---> GET http://monasticacademy.org/
# <--- 308 http://monasticacademy.org/ (14 bytes)
# ---> GET https://monasticacademy.org/
# <--- 308 https://monasticacademy.org/ (15 bytes)
# ---> GET https://www.monasticacademy.org/
# <--- 200 https://www.monasticacademy.org/ (31955 bytes)

test-curl-pre-resolved-https: setup-tests
	httptap -- bash -c "curl -s --resolve example.com:443:$(shell dig +short example.com | head -n 1) https://example.com > out"

# Output:
# ---> GET https://example.com/
# <--- 200 https://example.com/ (1256 bytes)

test-curl-pre-resolved-http: setup-tests
	httptap -- bash -c "curl -s --resolve example.com:80:$(shell dig +short example.com | head -n 1) http://example.com > out"

# Output:
# ---> GET http://example.com/
# <--- 200 http://example.com/ (1256 bytes)

# try curling ipv6.google.com, which has an ipv6 address only
test-curl-ipv6:
	./testing/httptap_test curl -sL https://ipv6.google.com

# ---> GET https://ipv6.google.com/
# <--- 200 https://ipv6.google.com/ (18791 bytes)

test-netcat: setup-tests
	httptap -- \
		bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' \
		| nc example.com 80 \
		> out"
	grep -A 1000000 "<!doctype html>" out | diff - testing/expected/example.com

# Output:
# ---> GET http://example.com/
# <--- 200 http://example.com/ (1256 bytes)

test-netcat-pre-resolved: setup-tests
	httptap -- \
		bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' \
		| nc $(shell dig +short example.com | head -n 1) 80 \
		> out"
	grep -A 1000000 "<!doctype html>" out | diff - testing/expected/example.com

# Output:
# ---> GET http://example.com/
# <--- 200 http://example.com/ (1256 bytes)

test-wget: setup-tests
	./testing/httptap_test wget -qO - https://example.com

# Output:
# ---> GET https://example.com/
# <--- 200 https://example.com/ (1256 bytes)

test-udp-11223: setup-tests
	httptap -- bash -c "echo 'hello udp' | socat udp4:1.2.3.4:11223 - "

test-udp-11223-two-udp-packets: setup-tests
	httptap -- bash -c "echo 'hello udp' | socat udp4:1.2.3.4:11223 - ; echo 'hello again udp' | socat udp4:1.2.3.4:11223 - "

test-socat-dns: setup-tests
	httptap -- bash -c "echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r | socat udp4:1.1.1.1:53 - | xxd"

# Output:
# 00000000: cfc9 8100 0001 0001 0000 0000 0a64 7563  .............duc
# 00000010: 6b64 7563 6b67 6f03 636f 6d00 0001 0001  kduckgo.com.....
# 00000020: 0a64 7563 6b64 7563 6b67 6f03 636f 6d00  .duckduckgo.com.
# 00000030: 0001 0001 0000 0e10 0004 3495 f627       ..........4..'

test-dig: setup-tests
	./testing/httptap_test dig +short -t a monasticacademy.org

test-dig-cloudflare: setup-tests
	./testing/httptap_test dig +short -t a monasticacademy.org @1.1.1.1

disabled-test-http3:
	./testing/httptap_test go run ./testing/http3get https://www.google.com

test-nslookup: setup-tests
	nslookup google.com | grep -A 10000 answer | grep Address > expected
	httptap -- bash -c "nslookup google.com | grep -A 10000 answer | grep Address > actual"
	diff actual expected

# should not generate extraneous error messages
test-nonexistent-domain: setup-tests
	./testing/httptap_test curl -qs https://nonexistent.monasticacademy.org

# Output:
# httptap exited with code 6

test-java: setup-tests
	javac testing/java/Example.java
	httptap -- java -cp testing/java Example 2>1 | grep -v JAVA_OPTIONS

# Output:
# ---> GET https://example.com/
# <--- 200 https://example.com/ (1256 bytes)

test-doh: setup-tests
	./testing/httptap_test curl -s --doh-url https://cloudflare-dns.com/dns-query https://www.example.com

# Output:
# ---> POST https://cloudflare-dns.com/dns-query
# <--- 200 https://cloudflare-dns.com/dns-query (143 bytes)
# ---> POST https://cloudflare-dns.com/dns-query
# <--- 200 https://cloudflare-dns.com/dns-query (167 bytes)
# ---> GET https://www.example.com/
# <--- 200 https://www.example.com/ (1256 bytes)

test-node: setup-tests
	./testing/httptap_test node testing/js/get.js

# Output:
# ---> GET https://www.example.com/
# <--- 200 https://www.example.com/ (1256 bytes)

test-deno: setup-tests
	./testing/httptap_test deno --allow-net testing/ts/get.ts

# Output:
# ---> GET https://example.com/
# <--- 200 https://example.com/ (1256 bytes)

not-working-test-bun: setup-tests
	./testing/httptap_test bun testing/ts/get.ts

# Output:
# ---> GET https://example.com/
# <--- 200 https://example.com/ (1256 bytes)

# Test running httptap inside itself
not-working-test-self: setup-tests
	httptap -- httptap curl https://www.example.com

# Test HAR output
test-har:
	httptap --dump-har out.har -- curl -Lso /dev/null https://monasticacademy.org
	jq '.log.entries[] | del(.response.content.text, .request.headers, .response.headers, .timings, .time, .startedDateTime)' out.har > filtered.har
	diff filtered.har testing/expected/monasticacademy.org.har

# Output:
# ---> GET https://monasticacademy.org/
# <--- 308 https://monasticacademy.org/ (15 bytes)
# ---> GET https://www.monasticacademy.org/
# <--- 200 https://www.monasticacademy.org/ (31955 bytes)

# These tests are currently broken

manual-test-nonroot-user: setup-tests
	./testing/httptap_test --user $(USER) -- bash -norc

# these tests require things that I do not want to install into github actions

manual-test-gcloud: setup-tests
	./testing/httptap_test gcloud compute instances list

# Test running inside sudo

test-sudo: setup-tests
	go build -o /tmp/httptap
	sudo /tmp/httptap echo "hello"

# Output:
# hello

test-sudo-no-new-user-namespace: setup-tests
	go build -o /tmp/httptap
	sudo /tmp/httptap --no-new-user-namespace -- curl -so out https://www.example.com

# Output:
# ---> GET https://example.com/
# <--- 200 https://example.com/ (1256 bytes)

manual-test-sudo-udp:
	go build -o /tmp/httptap
	go build -o /tmp/udpsend ./testing/udpsend
	sudo /tmp/httptap /tmp/udpsend httptap 1.2.3.4:11223

test-sudo-setcap-echo:
	go build -o /tmp/httptap
	sudo setcap 'cap_net_admin=ep cap_sys_admin=ep cap_dac_override=ep' /tmp/httptap
	/tmp/httptap --no-new-user-namespace -- echo "hello"

# Output:
# hello

test-sudo-setcap-curl:
	go build -o /tmp/httptap
	sudo setcap 'cap_net_admin=ep cap_sys_admin=ep cap_dac_override=ep' /tmp/httptap
	/tmp/httptap --no-new-user-namespace -- curl -so out https://www.example.com

# Output:
# ---> GET https://example.com/
# <--- 200 https://example.com/ (1256 bytes)

# Docker-based tests

manual-test-dockerized-ubuntu: setup-tests
	mkdir -p .build
	go build -o .build/httptap
	docker run \
		--interactive \
		--tty \
		--rm \
		--volume .:/src \
		--workdir /src \
		--cap-add SYS_ADMIN \
		--device /dev/net/tun:/dev/net/tun \
		ubuntu \
		.build/httptap --no-overlay -- curl -so out https://www.example.com

manual-test-dockerized-alpine: setup-tests
	mkdir -p .build
	CGO_ENABLED=0 go build -o .build/httptap
	docker run \
		--interactive \
		--tty \
		--rm \
		--volume .:/src \
		--workdir /src \
		--cap-add SYS_ADMIN \
		--device /dev/net/tun:/dev/net/tun \
		alpine/curl \
		.build/httptap --no-overlay -- curl -so out https://www.example.com

manual-test-dockerized-distroless: setup-tests
	mkdir -p .build
	CGO_ENABLED=0 go build -o .build/httptap
	CGO_ENABLED=0 go build -o .build/hi ./testing/hello
	docker run \
		--interactive \
		--tty \
		--rm \
		--volume .:/src \
		--workdir /src \
		--cap-add SYS_ADMIN \
		--device /dev/net/tun:/dev/net/tun \
		gcr.io/distroless/static-debian12 \
		.build/httptap --no-overlay -- .build/hi
