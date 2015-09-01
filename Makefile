PYTHON = /usr/bin/env python3
ROOT   = $(realpath .)/test-stage


.PHONY: doc-html
doc-html:
	$(PYTHON) setup.py install --root=$(ROOT) --install-lib=/
	env PYTHONPATH=$(ROOT) make html -C Doc


.PHONY: test-interactive
test-interactive:
	$(PYTHON) setup.py install --root=$(ROOT) --install-lib=/
	env PYTHONPATH=$(ROOT) $(PYTHON)


.PHONY: test-unittest
test-unittest:
	$(PYTHON) setup.py install --root=$(ROOT) --install-lib=/
	env PYTHONPATH=$(ROOT) $(PYTHON) -m unittest discover --verbose


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
	make clean -C Doc
