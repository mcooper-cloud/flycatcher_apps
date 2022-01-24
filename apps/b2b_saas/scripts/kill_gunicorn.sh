#!/bin/bash

for i in $(ps ax | grep gunicorn | cut -d' ' -f2); do
    kill -HUP $i;
done