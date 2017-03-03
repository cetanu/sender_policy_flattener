# Requires rpm-build, python-pip, python-virtualenv

SHELL := /bin/bash

test:
	virtualenv --system-site-packages venv
	source venv/bin/activate
	venv/bin/pip install --ignore-installed nose2
	venv/bin/pip install -r requirements.txt
	venv/bin/nose2 --verbose

clean:
	rm -vf MANIFEST
	rm -vrf build dist venv
	find . -name *.pyc -delete

build:
	python setup.py bdist_rpm --requires python-beautifulsoup4,python-schema,python-ipaddress,python-jinja2,python-yaml,python-requests
