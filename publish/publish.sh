#!/bin/sh

tar cf - -C ~/public_html . | nc -U /run/publish/daemon.sock

