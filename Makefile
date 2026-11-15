.PHONY: build test sample

build:
	mkdir -p build && scalac -d build src/Audit.scala src/Main.scala 2>&1 | grep -E 'error|exception' ; test -f build/csp/Main.class

test: build
	scalac -d build src/Audit.scala tests/Tests.scala 2>&1 | grep -E 'error|exception' ; scala -cp build csp.Tests

sample: build
	mkdir -p docs site
	bin/csp-audit examples 2>/dev/null > docs/sample-output.txt; true
	bin/csp-audit examples --tsv 2>/dev/null > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "csp-audit" "Audits saved HTTP response headers: Content-Security-Policy, HSTS, cookies, CORS and version disclosure. Scala." "Synthetic captures."
