#!/usr/bin/env bash

#set -ex

$PYTHON -m pip install conda/wheels/* --target zlogging/_extern -vv
$PYTHON -m pip install . -vv
