default: build

build:
	$(eval NAME    = $(shell grep -Pom1 "(?<=<Type>)[^<]+" manifest.xml))
	$(eval VERSION = $(shell grep -Pom1 "(?<=<Version>)[^<]+" manifest.xml))

	@echo "Building '$(NAME)-$(VERSION).zip' ..."
	zip -r9 $(NAME)-$(VERSION).zip *
