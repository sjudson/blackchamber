TESTS = test/*.test.js test/**/*.test.js
MOCHA = node_modules/.bin/mocha
MOD   = --require test/support/bootstrap.js

test:
	$(MOCHA) $(MOD) $(TESTS)

remove:
	-rm -r node_modules

.PHONY: test remove
