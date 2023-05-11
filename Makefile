VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
SHELL = zsh


init:
	python -m venv $(VENV)
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt

clean:
	rm -rf $(VENV)