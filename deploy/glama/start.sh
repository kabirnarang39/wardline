#!/bin/sh
# Starts the stub upstream in the background, then execs wardline in the
# foreground so it's PID 1 and receives signals correctly.
set -e
/usr/local/bin/mock_mcp 127.0.0.1:9000 &
exec /usr/local/bin/wardline serve --config /etc/wardline/wardline.yaml
