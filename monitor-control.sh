#!/bin/bash
# Control script for Local VirusTotal Download Monitor

PLIST="$HOME/Library/LaunchAgents/com.local-virustotal.monitor.plist"
LOG_FILE="$HOME/local-virustotal/monitor.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

case "$1" in
    start)
        echo -e "${GREEN}Starting Download Monitor...${NC}"
        launchctl load "$PLIST" 2>/dev/null
        if launchctl list | grep -q "com.local-virustotal.monitor"; then
            echo -e "${GREEN}✓ Monitor is running${NC}"
            echo -e "${CYAN}All downloads will be automatically scanned${NC}"
        else
            echo -e "${RED}Failed to start monitor${NC}"
        fi
        ;;

    stop)
        echo -e "${YELLOW}Stopping Download Monitor...${NC}"
        launchctl unload "$PLIST" 2>/dev/null
        echo -e "${GREEN}✓ Monitor stopped${NC}"
        ;;

    restart)
        echo -e "${YELLOW}Restarting Download Monitor...${NC}"
        launchctl unload "$PLIST" 2>/dev/null
        sleep 1
        launchctl load "$PLIST" 2>/dev/null
        echo -e "${GREEN}✓ Monitor restarted${NC}"
        ;;

    status)
        if launchctl list | grep -q "com.local-virustotal.monitor"; then
            echo -e "${GREEN}✓ Monitor is RUNNING${NC}"
            echo -e "${CYAN}Watching: ~/Downloads${NC}"
        else
            echo -e "${RED}✗ Monitor is NOT running${NC}"
            echo -e "${YELLOW}Start with: $0 start${NC}"
        fi
        ;;

    log)
        echo -e "${CYAN}Showing monitor log (Ctrl+C to exit):${NC}"
        tail -f "$LOG_FILE"
        ;;

    quarantine)
        QUARANTINE_DIR="$HOME/local-virustotal/quarantine"
        if [ -d "$QUARANTINE_DIR" ] && [ "$(ls -A $QUARANTINE_DIR 2>/dev/null)" ]; then
            echo -e "${RED}Quarantined files:${NC}"
            ls -lh "$QUARANTINE_DIR"
        else
            echo -e "${GREEN}No files in quarantine${NC}"
        fi
        ;;

    clear-quarantine)
        QUARANTINE_DIR="$HOME/local-virustotal/quarantine"
        echo -e "${YELLOW}WARNING: This will permanently delete all quarantined files!${NC}"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            rm -rf "$QUARANTINE_DIR"/*
            echo -e "${GREEN}Quarantine cleared${NC}"
        else
            echo -e "${CYAN}Cancelled${NC}"
        fi
        ;;

    enable-autostart)
        echo -e "${GREEN}Enabling auto-start on login...${NC}"
        launchctl load "$PLIST" 2>/dev/null
        echo -e "${GREEN}✓ Monitor will start automatically when you log in${NC}"
        ;;

    disable-autostart)
        echo -e "${YELLOW}Disabling auto-start...${NC}"
        launchctl unload "$PLIST" 2>/dev/null
        echo -e "${GREEN}✓ Auto-start disabled${NC}"
        ;;

    *)
        echo -e "${CYAN}Local VirusTotal - Download Monitor Control${NC}"
        echo ""
        echo "Usage: $0 {command}"
        echo ""
        echo "Commands:"
        echo "  start              - Start the monitor"
        echo "  stop               - Stop the monitor"
        echo "  restart            - Restart the monitor"
        echo "  status             - Check if monitor is running"
        echo "  log                - View live monitor log"
        echo "  quarantine         - List quarantined files"
        echo "  clear-quarantine   - Delete all quarantined files"
        echo "  enable-autostart   - Start monitor on login"
        echo "  disable-autostart  - Don't start on login"
        echo ""
        ;;
esac
