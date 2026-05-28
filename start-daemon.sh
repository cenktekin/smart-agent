#!/bin/bash
cd /home/cenk/Belgeler/projects/smart-agent
rm -f data/daemon.pid
exec .venv/bin/python cli.py daemon-start --silent
