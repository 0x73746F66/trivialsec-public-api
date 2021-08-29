SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
CONAINER_NAME	= registry.gitlab.com/trivialsec/public-api/${BUILD_ENV}
.ONESHELL:
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

ifndef CI_BUILD_REF
	CI_BUILD_REF = local
endif

prep: ## Cleanup tmp files
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null
	@rm -f **/*.zip **/*.tar **/*.tgz **/*.gz
	@rm -rf build python-libs

python-libs: prep ## download and install the trivialsec python libs locally (for IDE completions)
	yes | pip uninstall -q trivialsec-common
	@$(shell git clone -q -c advice.detachedHead=false --depth 1 --branch ${COMMON_VERSION} --single-branch https://${DOCKER_USER}:${DOCKER_PASSWORD}@gitlab.com/trivialsec/python-common.git python-libs)
	cd python-libs
	make install

install-deps: python-libs ## Just the minimal local deps for IDE completions
	pip install -q -U pip setuptools wheel semgrep pylint
	pip install -q -U --no-cache-dir --find-links=python-libs/build/wheel --no-index --isolated -r requirements.txt

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py
	semgrep -q --strict --config p/minusworld.flask-xss --lang=py src/**/*.py

pylint-ci: ## run pylint for CI
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

semgrep-xss-ci: ## run Flask XSS semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-flask-xss.json --json --config p/minusworld.flask-xss --lang=py src/**/*.py

test-all: semgrep-xss-ci semgrep-sast-ci pylint-ci ## Run all CI tests

build: ## Builds images using docker cli directly for CI
	@docker build -q --compress $(BUILD_ARGS) \
		-t $(CONAINER_NAME):$(CI_BUILD_REF) \
		--cache-from $(CONAINER_NAME):latest \
        --build-arg COMMON_VERSION=$(COMMON_VERSION) \
        --build-arg BUILD_ENV=$(BUILD_ENV) \
        --build-arg GITLAB_USER=$(DOCKER_USER) \
        --build-arg GITLAB_PASSWORD=$(DOCKER_PASSWORD) \
		--build-arg PYTHONUNBUFFERED=1 \
        --build-arg PYTHONUTF8=1 \
        --build-arg CFLAGS='-O0' \
        --build-arg STATICBUILD=1 \
        --build-arg LC_ALL=C.UTF-8 \
        --build-arg LANG=C.UTF-8 .

push-tagged: ## Push tagged image
	docker push -q $(CONAINER_NAME):${CI_BUILD_REF}

push-ci: ## Push latest image using docker cli directly for CI
	docker tag $(CONAINER_NAME):${CI_BUILD_REF} $(CONAINER_NAME):latest
	docker push -q $(CONAINER_NAME):latest

pull-base: ## pulls latest base image
	docker pull -q registry.gitlab.com/trivialsec/containers-common/python:latest

build-ci: pull pull-base build ## Builds from latest base image

pull: ## pulls latest image
	docker pull -q $(CONAINER_NAME):latest

rebuild: down build-ci ## Brings down the stack and builds it anew

debug:
	docker-compose run api python3 -u -d -X dev uwsgi.py

docker-login: ## login to docker cli using $DOCKER_USER and $DOCKER_PASSWORD
	@echo $(shell [ -z "${DOCKER_PASSWORD}" ] && echo "DOCKER_PASSWORD missing" )
	@echo ${DOCKER_PASSWORD} | docker login -u ${DOCKER_USER} --password-stdin registry.gitlab.com

up: prep ## Start the api
	docker-compose up -d

down: ## Stop the api
	@docker-compose down --remove-orphans

restart: down up ## restarts the api

test-hmac:
	./test-hmac-local.sh sha256 GET /v1/test
	./test-hmac-local.sh sha512 GET /v1/test
	./test-hmac-local.sh sha3-256 GET /v1/test
	./test-hmac-local.sh sha3-384 GET /v1/test
	./test-hmac-local.sh sha3-512 GET /v1/test
	./test-hmac-local.sh blake2b512 GET /v1/test
	./test-hmac-local.sh sha256 POST /v1/test '{"domain_name":"trivialsec.com"}'
	./test-hmac-local.sh sha512 POST /v1/test '{"domain_name":"trivialsec.com"}'
	./test-hmac-local.sh sha3-256 POST /v1/test '{"domain_name":"trivialsec.com"}'
	./test-hmac-local.sh sha3-384 POST /v1/test '{"domain_name":"trivialsec.com"}'
	./test-hmac-local.sh sha3-512 POST /v1/test '{"domain_name":"trivialsec.com"}'
	./test-hmac-local.sh blake2b512 POST /v1/test '{"domain_name":"trivialsec.com"}'
