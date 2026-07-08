#!/bin/bash

# On Linux with --network host, host.docker.internal doesn't resolve.
# Fall back to localhost so Ollama is reachable either way.
if [ "${OLLAMA_HOST}" = "http://host.docker.internal:11434" ]; then
    if ! getent hosts host.docker.internal > /dev/null 2>&1; then
        export OLLAMA_HOST="http://localhost:11434"
    fi
fi

echo "[mark2] Target  : ${TARGET}"
echo "[mark2] Backend : ${LLM_PROVIDER} / ${OLLAMA_MODEL:-claude}"

python3 /agent.py --target "$TARGET"
