#!/bin/bash

git config --global user.name "Admin"
git config --global user.email "admin@corp.com"

cd /app
git init

git add README.md
git commit -m "Add README with expected features"

git add config-tool.py
git commit -m "Add v1 of code"

git add .gitignore
git commit -m "Add generic gitignore to avoid clobbering the repo"