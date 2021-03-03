SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
APP_NAME = api
LOCAL_CACHE = /tmp/trivialsec

.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

CMD_AWS := aws
ifdef AWS_PROFILE
CMD_AWS += --profile $(AWS_PROFILE)
endif
ifdef AWS_REGION
CMD_AWS += --region $(AWS_REGION)
endif

prep:
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	find . -type d -name '__pycache__' -delete 2>/dev/null || true
	find . -type f -name '*.DS_Store' -delete 2>/dev/null || true
	@rm *.zip *.whl || true
	@rm -rf build || true

common: prep
	yes | pip uninstall -q trivialsec-common
	aws s3 cp --only-show-errors s3://trivialsec-assets/deploy-packages/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl
	aws s3 cp --only-show-errors s3://trivialsec-assets/deploy-packages/$(COMMON_VERSION)/build.tgz build.tgz
	tar -xzvf build.tgz
	pip install -q --no-cache-dir --find-links=build/wheel --no-index trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl

common-dev: prep ## Install trivialsec_common lib from local build
	yes | pip uninstall -q trivialsec-common
	cp -fu $(LOCAL_CACHE)/build.tgz build.tgz
	cp -fu $(LOCAL_CACHE)/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl
	tar -xzvf build.tgz
	pip install -q --no-cache-dir --find-links=build/wheel --no-index trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl

install-dev:
	pip install -q -U pip setuptools pylint wheel awscli semgrep
	pip install -q -U --no-cache-dir --isolated -r ./docker/requirements.txt

lint:
	pylint --jobs=0 --persistent=y --errors-only src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/ci --lang=py src/**/*.py
	semgrep -q --strict --config p/minusworld.flask-xss --lang=py src/**/*.py

test-local:
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

build: prep package-dev ## Build compressed container
	docker-compose build --compress

buildnc: prep package-dev ## Clean build docker
	docker-compose build --no-cache --compress

rebuild: down build

docker-clean: ## Fixes some issues with docker
	docker rmi $(docker images -qaf "dangling=true")
	yes | docker system prune
	sudo service docker restart

docker-purge: ## tries to compeltely remove all docker files and start clean
	docker rmi $(docker images -qa)
	yes | docker system prune
	sudo service docker stop
	sudo rm -rf /tmp/docker.backup/
	sudo cp -Pfr /var/lib/docker /tmp/docker.backup
	sudo rm -rf /var/lib/docker
	sudo service docker start

up: prep ## Start the app
	docker-compose up -d $(APP_NAME)

run: prep
	docker-compose run -d --rm -p "8080:8080" --name $(APP_NAME) --entrypoint python3.8 $(APP_NAME) run.py

down: ## Stop the app
	@docker-compose down

restart: down run

package: prep
	zip -9rq $(APP_NAME).zip src -x '*.pyc' -x '__pycache__' -x '*.DS_Store'
	zip -uj9q $(APP_NAME).zip docker/requirements.txt

package-upload: package
	$(CMD_AWS) s3 cp --only-show-errors $(APP_NAME).zip s3://trivialsec-assets/deploy-packages/$(COMMON_VERSION)/$(APP_NAME).zip
	$(CMD_AWS) s3 cp --only-show-errors deploy/nginx.conf s3://trivialsec-assets/deploy-packages/$(COMMON_VERSION)/$(APP_NAME)-nginx.conf

package-dev: common-dev package
	zip -d $(APP_NAME).zip src/.flaskenv
	$(CMD_AWS) s3 cp --only-show-errors $(APP_NAME).zip s3://trivialsec-assets/dev/$(COMMON_VERSION)/$(APP_NAME).zip
