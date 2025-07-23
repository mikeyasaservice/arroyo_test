#!/bin/bash
# Health check script for monitoring

PIPELINES=("toolshell-core" "toolshell-analytics" "toolshell-alerts")
EXIT_CODE=0

for pipeline in "${PIPELINES[@]}"; do
    status=$(arroyo pipeline status "${pipeline}" 2>/dev/null | grep -o 'running' | head -1)
    if [ "${status}" != "running" ]; then
        echo "Pipeline ${pipeline} is not healthy"
        EXIT_CODE=1
    fi
done

exit ${EXIT_CODE}
