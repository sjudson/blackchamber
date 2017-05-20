TESTS = test/*.test.js test/**/*.test.js
MOCHA = node_modules/.bin/mocha

test:
	$(MOCHA) $(TESTS)

remove:
	-rm -r node_modules

.PHONY: test remove
