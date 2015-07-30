PYTHON = /usr/bin/env python3
ROOT   = ./test-stage


.PHONY: test-interactive
test-interactive:
	$(PYTHON) setup.py install --root=$(ROOT) --install-lib=/
	env PYTHONPATH=$(ROOT) $(PYTHON)


.PHONY: test-interactive-with-gdb
test-interactive-with-gdb:
	$(PYTHON) setup.py install --root=$(ROOT) --install-lib=/
	env PYTHONPATH=$(ROOT) gdb python3


.PHONY: test-interactive-with-valgrind
test-interactive-with-valgrind:
	$(PYTHON) setup.py install --root=$(ROOT) --install-lib=/
	env PYTHONPATH=$(ROOT) valgrind --tool=memcheck --leak-check=yes python3


.PHONY: pypi-upload
pypi-upload: clean
	git branch --list --no-color | grep -F '* master' || exit 1
	$(PYTHON) setup.py sdist upload


.PHONY: clean
clean:
	rm -rf dist build $(ROOT) Lib/libldap.egg-info
