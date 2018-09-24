#!/bin/bash
DIR=$(cd $(dirname ${BASH_SOURCE:-$0}); pwd)
HOST=${HOST:-"localhost"}
PORT=${PORT:-"9999"}

cd $DIR;
php -S $HOST:$PORT -t public