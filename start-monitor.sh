#!/bin/bash
# Start the Downloads folder monitor
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/venv/bin/activate"
python3 "$SCRIPT_DIR/monitor.py" "$@"
