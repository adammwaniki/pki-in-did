# PKI in DIDs -- demonstration.
#
#   make images   build the container images
#   make setup    build the whole PKI, DIDs and credentials from nothing
#   make test     unit tests (hermetic) then integration tests against the live stack
#   make demo     run all four recorded parts in order
#   make reset    reissue everything; the National Root CA is kept
#   make record   record all five parts to recordings/

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

COMPOSE := docker compose -p pki-in-did

.PHONY: help
help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST)

## images      build the container images
.PHONY: images
images:
	$(COMPOSE) build
	docker build -t pki-in-did/verifier -f images/verifier/Dockerfile .
	docker build -t pki-in-did/ca-tools -f images/ca-tools/Dockerfile .
	docker build -t pki-in-did/tester   -f images/tester/Dockerfile .
	docker build -t pki-in-did/recorder -f images/recorder/Dockerfile .

## setup       build the PKI, start the stack, issue the credentials
.PHONY: setup
setup: images
	scripts/10-offline-root.sh
	scripts/11-issuing-ca-csr.sh
	scripts/12-offline-sign-ca.sh
	scripts/05-publish-root.sh
	scripts/15-web-tls.sh
	scripts/20-issuer-certs.sh
	scripts/25-waltid-config.sh
	scripts/30-did-documents.sh
	scripts/50-publish-crl.sh
	scripts/98-compose-up.sh
	scripts/40-issue-credentials.sh
	scripts/70-fingerprint.sh
	scripts/80-seed-offline-cache.sh
	@printf '\n  ready. try: make demo\n\n'

## up          start the stack
.PHONY: up
up:
	$(COMPOSE) up -d

## down        stop the stack
.PHONY: down
down:
	$(COMPOSE) down

## logs        follow the stack's logs
.PHONY: logs
logs:
	$(COMPOSE) logs -f

## test        unit tests, then integration tests against the live stack
.PHONY: test
test: test-unit test-integration

## test-unit   hermetic tests: no Docker network, no live stack
.PHONY: test-unit
test-unit:
	scripts/pytest.sh tests/unit -q

## test-integration   tests against the running stack
.PHONY: test-integration
test-integration:
	PKI_DEMO_STACK=1 scripts/pytest.sh tests/integration -q

## demo        run the four recorded parts in order
.PHONY: demo
demo:
	demo/part1-happy-online.sh
	demo/part2-happy-offline.sh
	demo/part3-revocation-online.sh
	demo/part4-revocation-offline.sh
	demo/part5-the-gap.sh

## reset       reissue every certificate and credential (the root is kept)
.PHONY: reset
reset:
	scripts/00-reset.sh

## record      record every part to recordings/
.PHONY: record
record:
	record/record.sh all

## public-setup   build and start the public profile on the labs.* hostnames
.PHONY: public-setup
public-setup: images
	DOMAINS_FILE=config/domains.public.env scripts/10-offline-root.sh
	DOMAINS_FILE=config/domains.public.env scripts/11-issuing-ca-csr.sh
	DOMAINS_FILE=config/domains.public.env scripts/12-offline-sign-ca.sh
	DOMAINS_FILE=config/domains.public.env scripts/05-publish-root.sh
	DOMAINS_FILE=config/domains.public.env scripts/20-issuer-certs.sh
	DOMAINS_FILE=config/domains.public.env scripts/25-waltid-config.sh
	DOMAINS_FILE=config/domains.public.env scripts/30-did-documents.sh
	DOMAINS_FILE=config/domains.public.env scripts/50-publish-crl.sh
	DOMAINS_FILE=config/domains.public.env scripts/98-compose-up.sh
	DOMAINS_FILE=config/domains.public.env scripts/40-issue-credentials.sh
	@printf '\n  built. now give Caddy the hostnames -- see deploy/README.md step 2\n\n'

## public-check    verify the public deployment from outside, online and offline
.PHONY: public-check
public-check:
	DOMAINS_FILE=config/domains.public.env scripts/99-public-check.sh

## public-down     stop the public profile
.PHONY: public-down
public-down:
	DOMAINS_FILE=config/domains.public.env scripts/98-compose-up.sh --down

## clean       remove all generated state, including the root. Destructive.
.PHONY: clean
clean:
	$(COMPOSE) down -v --remove-orphans || true
	rm -rf state
