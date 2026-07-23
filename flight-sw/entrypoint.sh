#!/bin/sh
# Stage the firmware image on the shared volume so the ground station operator
# console can serve it for download, then boot the OBC.
mkdir -p /firmware
cp -f /app/flight_sw /firmware/flight_sw 2>/dev/null || true
exec /app/flight_sw
