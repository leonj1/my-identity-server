.PHONY: build start stop restart logs clean integration

build:
	docker-compose build

start:
	docker-compose up -d

stop:
	docker-compose down

restart: stop start

logs:
	docker-compose logs -f

clean:
	docker-compose down -v

integration:
	# Clean up any existing containers and volumes first
	docker-compose -f docker-compose.integration.yml down -v --remove-orphans
	# Remove any existing images to ensure a clean build
	docker rmi -f my-identity-server_identity-server my-identity-server_integration-client 2>/dev/null || true
	# Build the images
	docker-compose -f docker-compose.integration.yml build --no-cache
	# Run the integration test
	docker-compose -f docker-compose.integration.yml up --abort-on-container-exit --remove-orphans
	# Clean up after the test
	docker-compose -f docker-compose.integration.yml down -v