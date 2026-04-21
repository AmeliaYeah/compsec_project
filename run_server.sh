#!/bin/sh

# delete if persistence is needed
rm logs/*
rm data/*.json

# start the webserver
python3 -m compsec_project.app