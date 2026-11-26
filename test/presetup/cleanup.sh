#!/bin/sh

# Stop a locally started VSM (integration mode)
if [ -f vsm.pid ]; then
    kill "$(cat vsm.pid)" 2>/dev/null || true
fi
rm -f vsm.pid vsm.log

# Stop docker compose
docker compose -f docker-compose-common.yml -f docker-compose-e2e.yml down

# Delete terraform tfstate
rm -f test/presetup/vsmdevel.tfstate