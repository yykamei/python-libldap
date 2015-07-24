PYTHON        = /usr/bin/env python3
ROOT          = ./test-stage


.PHONY: test-interactive
test-interactive:
	$(PYTHON) setup.py install --root=$(ROOT) --install-lib=/
	env PYTHONPATH=$(ROOT) $(PYTHON)


.PHONY: test-interactive-with-gdb
test-interactive-with-gdb:
	$(PYTHON) setup.py install --root=$(ROOT) --install-lib=/
	env PYTHONPATH=$(ROOT) gdb $(PYTHON)


.PHONY: clean
clean:
	rm -rf build $(ROOT)
