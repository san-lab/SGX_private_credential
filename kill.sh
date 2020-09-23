#!/bin/bash
ps -ef | grep '[s]erver.py' | awk '{print $2}' | xargs kill