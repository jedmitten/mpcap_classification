VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
SHELL = zsh

.PHONY: init clean features


init:
	python -m venv $(VENV)
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt

clean:
	rm -rf $(VENV)

features:
	$(PYTHON) generate_features.py