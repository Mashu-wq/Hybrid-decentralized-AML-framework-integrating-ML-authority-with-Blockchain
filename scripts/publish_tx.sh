#!/usr/bin/env bash
# publish_tx.sh — Publish a JSON transaction to Kafka transactions.raw topic.
#
# Usage:
#   ./scripts/publish_tx.sh '{"tx_hash":"tx-001","customer_id":"...","amount":250, ...}'
#
# Or pipe from a file:
#   cat my_tx.json | ./scripts/publish_tx.sh

set -euo pipefail

KAFKA_CONTAINER="${KAFKA_CONTAINER:-fds-kafka}"
TOPIC="${TOPIC:-transactions.raw}"

if [ -t 0 ] && [ $# -eq 0 ]; then
    echo "Usage: $0 '<json>' OR echo '<json>' | $0" >&2
    exit 1
fi

if [ $# -ge 1 ]; then
    JSON="$1"
else
    JSON="$(cat)"
fi

# Validate JSON before publishing
if ! echo "$JSON" | python3 -m json.tool > /dev/null 2>&1; then
    echo "ERROR: Invalid JSON. Check for line breaks or unescaped characters." >&2
    echo "Input was: $JSON" >&2
    exit 1
fi

# Publish as single line (kafka-console-producer sends one message per line)
echo "$JSON" | tr -d '\n' | \
    docker exec -i "$KAFKA_CONTAINER" kafka-console-producer \
        --broker-list localhost:9092 \
        --topic "$TOPIC" 2>/dev/null

echo "Published to $TOPIC" >&2
