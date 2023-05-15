VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
SHELL = zsh

.PHONY: init clean readme report documentation


init:
	python -m venv $(VENV)
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt

clean:
	rm -rf $(VENV)

readme:
	@cat markdown/readme_cruft.md > README.md
	@echo "" >> README.md
	@echo "" >> README.md
	@cat markdown/running.md >> README.md
	@echo "" >> README.md
	@echo "" >> README.md
	@cat markdown/testing.md >> README.md
	@echo "" >> README.md
	@echo "" >> README.md
	@cat markdown/challenge.md >> README.md
	@echo README.md was updated

report:
	@cat markdown/report_header.md > report.md
	@echo "" >> README.md
	@echo "" >> README.md
	@cat markdown/pipeline_diagram.md >> README.md
	@echo report.md was updated

documentation: readme report
