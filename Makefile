.DEFAULT_GOAL := help

PYTHON ?= python

ifeq ($(OS),Windows_NT)
VENV_PYTHON := .venv/Scripts/python.exe
else
VENV_PYTHON := .venv/bin/python
endif

.PHONY: help all setup run test health

help:
	@echo "Sentinel commands:"
	@echo "  make setup  Create the virtual environment and install dependencies"
	@echo "  make run    Start the API server"
	@echo "  make test   Run the test suite"
	@echo "  make health Check the running API health endpoint"
	@echo "  make all    Set up the environment and run tests"

all: setup test

setup:
	$(PYTHON) -m venv .venv
	$(VENV_PYTHON) -m pip install -r requirements.txt

run:
	$(VENV_PYTHON) -m uvicorn sentinel.app.main:app --reload

test:
	$(VENV_PYTHON) -m pytest

health:
	$(VENV_PYTHON) -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())"