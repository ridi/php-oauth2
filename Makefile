.PHONY: dist

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install:
	@composer install --working-dir=lib/Silex
	@composer install --working-dir=lib/Symfony
	@composer install

update:
	@composer update --working-dir=lib/Silex
	@composer update --working-dir=lib/Symfony
	@composer update

test:
	@lib/Silex/vendor/bin/phpunit
	@lib/Symfony/vendor/bin/phpunit --bootstrap tests/Symfony/index.php tests/Symfony
