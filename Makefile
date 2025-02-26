default: run

force:

build:
	go build

clean: force
	rm -rf out

test:
	go run ./testing/run-tests

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

# Test cases that run in CI

test-echo: install
	httptap -- echo "hello"    	# Output: hello

test-netcat: install
	httptap -- \
		bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' \
		| nc example.com 80 > out"
	grep -A 1000000 "<!doctype html>" out | diff - testing/expected/example.com

# Output:
# ---> GET http://example.com/
# <--- 200 http://example.com/ (1256 bytes)

test-netcat-pre-resolved: install
	httptap -- \
		bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' \
		| nc $(shell dig +short example.com | head -n 1) 80
		> out"
	grep -A 1000000 "<!doctype html>" out | diff - testing/expected/example.com

# Output:
# ---> GET http://example.com/
# <--- 200 http://example.com/ (1256 bytes)

manual-test-curl: install
	httptap -- bash -c "curl -s https://example.com > out"

manual-test-curl-non-tls: install
	httptap -- bash -c "curl -s http://example.com > out"

manual-test-curl-monasticacademy: install
	httptap -- bash -c "curl -sL http://monasticacademy.org > out"

manual-test-curl-pre-resolved: install
	httptap -- bash -c "curl -s --resolve example.com:443:93.184.215.14 https://example.com > out"

manual-test-curl-pre-resolved-non-tls: install
	httptap -- bash -c "curl -s --resolve example.com:80:93.184.215.14 http://example.com > out"

# try curling ipv6.google.com, which has an ipv6 address only
manual-test-curl-ipv6:
	httptap -- bash -c "curl -sL https://ipv6.google.com > out"

manual-test-http3:
	cd experiments/http3get; go build -o /tmp/http3get; cd -
	httptap -- /tmp/http3get https://www.google.com

# works with gvisor stack but not homegrown stack
manual-test-wget: install
	httptap -- wget https://example.com -O out

manual-test-udp-11223: install
	httptap -- bash -c "echo 'hello udp' | socat udp4:1.2.3.4:11223 - "

manual-test-two-udp-packets: install
	httptap -- bash -c "echo 'hello udp' | socat udp4:1.2.3.4:11223 - ; echo 'hello again udp' | socat udp4:1.2.3.4:11223 - "

manual-test-socat-dns: install
	httptap -- bash -c "echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r | socat udp4:1.1.1.1:53 - | xxd"

manual-test-dig: install
	httptap -- dig -t a google.com

manual-test-dig-1111: install
	httptap -- dig -t a google.com @1.1.1.1

manual-test-nslookup: install
	httptap -- nslookup google.com

# should not generate extraneous error messages
manual-test-nonexistent-domain: install
	httptap -- curl https://notarealdomain.monasticacademy.org

manual-test-netcat-11223: install
	httptap -- bash -c "netcat example.com 11223 < /dev/null"

manual-test-java: install
	javac experiments/java/Example.java
	httptap -- java -cp experiments/java Example

manual-test-doh: install
	httptap -- curl --doh-url https://cloudflare-dns.com/dns-query https://www.example.com

manual-test-node: install
	httptap node experiments/js/get.js

manual-test-deno: install
	httptap -- deno --allow-net experiments/ts/get.ts

manual-test-bun: install
	httptap -- bun experiments/ts/get.ts

manual-test-self: install
	httptap httptap curl https://www.example.com

# Test HAR output

manual-test-har:
	httptap --dump-har out.har -- curl -Lso /dev/null https://monasticacademy.org

# These tests are currently broken

manual-test-nonroot-user: install
	httptap --user $(USER) -- bash -norc

# these tests require things that I do not want to install into github actions

manual-test-gcloud: install
	httptap -- gcloud compute instances list

# docker-based tests

manual-test-dockerized-ubuntu: install
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

manual-test-dockerized-alpine: install
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

manual-test-dockerized-distroless: install
	mkdir -p .build
	CGO_ENABLED=0 go build -o .build/httptap
	CGO_ENABLED=0 go build -o .build/hi ./experiments/hello
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

# tests that require sudo

manual-test-sudo: install
	go build -o /tmp/httptap .
	sudo /tmp/httptap bash

manual-test-no-new-user-namespace: install
	go build -o /tmp/httptap .
	sudo /tmp/httptap --no-new-user-namespace -- curl -so out https://www.example.com

manual-test-udp-experiment:
	go build -o /tmp/httptap
	go build -o /tmp/udp-experiment ./experiments/udp
	sudo /tmp/httptap /tmp/udp-experiment httptap 1.2.3.4:11223

# tests that require setcap

manual-test-setcap:
	go build -o /tmp/httptap
	sudo setcap 'cap_net_admin=ep cap_sys_admin=ep cap_dac_override=ep' /tmp/httptap
	/tmp/httptap --no-new-user-namespace -- curl -so out https://www.example.com
