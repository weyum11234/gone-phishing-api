#!/bin/bash
export FLASK_APP=./gone-phishing/index.py
pipenv run flask --debug run -h 0.0.0.0