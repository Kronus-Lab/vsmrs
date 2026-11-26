#!/bin/sh

MODE=$1

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

# Check if development environment is already up
if docker ps | grep -q vsm; then
    echo "Development environment up or broken. Please use cleanup task first"
    exit 1
fi

# Start docker compose
docker compose -f docker-compose-common.yml -f docker-compose-$MODE.yml up -d 

# Switch to presetup folder
cd test/presetup

# Wait for stack to be up
./wait.sh

# Configure using Terraform
tofu init --upgrade
tofu apply --auto-approve

if [ "$MODE" = "integration" ]; then
    cd "$ROOT_DIR"
    cargo build --release || exit 1
    nohup ./target/release/vsm > vsm.log 2>&1 &
    echo $! > vsm.pid
    for _ in $(seq 1 60); do
        status=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/ || true)
        if [ "$status" = "302" ]; then
            echo "VSM ready on localhost:3000 (HTTP $status)"
            exit 0
        fi
        echo "Waiting for VSM on localhost:3000 (HTTP ${status:-none})"
        sleep 1
    done
    echo "VSM did not become ready; log follows:"
    cat vsm.log
    exit 1
fi
