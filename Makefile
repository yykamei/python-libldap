ROOT   = ./test-stage
PREFIX = /bbb

.PHONY: install
install:
	python3.4 setup.py install --root=$(ROOT) --prefix=$(PREFIX)

.PHONY: test
test:
	env PYTHONPATH=$(ROOT)$(PREFIX)/lib/python3.4/site-packages gdb python3.4

.PHONY: clean
clean:
	rm -rf build $(ROOT) $(PREFIX)
