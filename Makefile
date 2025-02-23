
build:
	go build

clean: force
	rm -rf out

run: clean
	go run . bash

force:

# Targets beginning with "test-" are run automatically in CI


webui-sleep-forever: clean
	go run . --webui :5000 -- sleep infinity

webui-curl-loop: clean
	go run . --webui :5000 -- bash -c "while true; do echo "curling..."; curl -s https://www.example.com > out; sleep 1; done"

tcpdump-port-11223:
	sudo tcpdump -i lo 'tcp port 11223'

# Test cases

test-with-hello: clean
	go run . -- go run ./experiments/hello

test-with-netcat-http: clean
	go run . -- bash -c "printf 'GET / HTTP/1.1\r\nHOST: example.com\r\nUser-Agent: nc\r\n\r\n' | nc 93.184.215.14 80 > out"

test-with-curl: clean
	go run . -- bash -c "curl -s https://example.com > out"

test-with-curl-non-tls: clean
	go run . -- bash -c "curl -s http://example.com > out"

test-with-curl-monasticacademy: clean
	go run . -- bash -c "curl -sL http://monasticacademy.org > out"

test-with-curl-pre-resolved: clean
	go run . -- bash -c "curl -s --resolve example.com:443:93.184.215.14 https://example.com > out"

test-with-curl-pre-resolved-non-tls: clean
	go run . -- bash -c "curl -s --resolve example.com:80:93.184.215.14 http://example.com > out"

# try curling ipv6.google.com, which has an ipv6 address only
test-with-curl-ipv6:
	go run . -- bash -c "curl -sL https://ipv6.google.com > out"

test-with-http3:
	cd experiments/http3get; go build -o /tmp/http3get; cd -
	go run . -- /tmp/http3get

# works with gvisor stack but not homegrown stack
test-with-wget: clean
	go run . -- wget https://example.com -O out

test-with-udp-11223: clean
	go run . -- bash -c "echo 'hello udp' | socat udp4:1.2.3.4:11223 - "

test-with-two-udp-packets: clean
	go run . -- bash -c "echo 'hello udp' | socat udp4:1.2.3.4:11223 - ; echo 'hello again udp' | socat udp4:1.2.3.4:11223 - "

test-with-socat-dns: clean
	go run . -- bash -c "echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r | socat udp4:1.1.1.1:53 - | xxd"

test-with-dig: clean
	go run . -- dig -t a google.com

test-with-dig-1111: clean
	go run . -- dig -t a google.com @1.1.1.1

test-with-nslookup: clean
	go run . -- nslookup google.com

# should not generate extraneous error messages
test-nonexistent-domain: clean:
	go run . -- curl https://notarealdomain.monasticacademy.org

test-with-netcat-11223: clean
	go run . -- bash -c "netcat example.com 11223 < /dev/null"

test-with-java: clean
	javac experiments/java/Example.java
	go run . -- java -cp experiments/java Example

test-with-doh: clean
	go run . -- curl --doh-url https://cloudflare-dns.com/dns-query https://www.example.com

test-with-node: clean
	go run . node experiments/js/get.js

test-with-deno: clean
	go run . -- deno --allow-net experiments/ts/get.ts

test-with-bun: clean
	go run . -- bun experiments/ts/get.ts

test-with-self: clean
	go run . go run . curl https://www.example.com

# Test HAR output

test-with-har:
	go run . --dump-har out.har -- curl -Lso /dev/null https://monasticacademy.org

# These tests are currently broken

broken-test-with-nonroot-user: clean
	go run . --user $(USER) -- bash -norc

# these tests require things that I do not want to install into github actions

local-test-with-gcloud: clean
	go run . -- gcloud compute instances list

# docker-based tests

docker-test: clean
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

docker-test-with-alpine: clean
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

docker-test-with-distroless: clean
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

sudo-test: clean
	go build -o /tmp/httptap .
	sudo /tmp/httptap bash

sudo-test-with-no-new-user-namespace: clean
	go build -o /tmp/httptap .
	sudo /tmp/httptap --no-new-user-namespace -- curl -so out https://www.example.com

sudo-test-with-udp-experiment:
	go build -o /tmp/httptap
	go build -o /tmp/udp-experiment ./experiments/udp
	sudo /tmp/httptap /tmp/udp-experiment httptap 1.2.3.4:11223

# tests that require setcap

setcap-test-with-setcap:
	go build -o /tmp/httptap
	sudo setcap 'cap_net_admin=ep cap_sys_admin=ep cap_dac_override=ep' /tmp/httptap
	/tmp/httptap --no-new-user-namespace -- curl -so out https://www.example.com
