#!/bin/bash
# Run AgentDojo benchmarks in batches to avoid rate limits

SUITE="${1:-workspace}"
DELAY="${2:-30}"  # Delay between tasks in seconds
OUTPUT_BASE="results/${SUITE}"

echo "Running AgentDojo benchmarks for suite: $SUITE"
echo "Delay between tasks: ${DELAY}s"
echo ""

# Get all user tasks for the suite
TASKS=(user_task_0 user_task_1 user_task_3 user_task_4 user_task_5 user_task_6 user_task_7 user_task_8 user_task_9)

# Run each task individually
for task in "${TASKS[@]}"; do
    echo "========================================="
    echo "Running task: $task"
    echo "========================================="
    
    OPENAI_API_KEY=$OPENAI_API_KEY \
    /opt/homebrew/Caskroom/miniconda/base/envs/agentdojo/bin/python \
      -m benchmarks.agentdojo.evaluate \
      --suite "$SUITE" \
      --compare \
      --tasks "$task"
    
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "✓ Task $task completed successfully"
    else
        echo "✗ Task $task failed with exit code $EXIT_CODE"
        
        # If rate limited, wait longer
        if grep -q "rate_limit" <<< "$OUTPUT"; then
            echo "Rate limit detected, waiting 60s..."
            sleep 60
        fi
    fi
    
    # Wait before next task
    if [ "$task" != "${TASKS[-1]}" ]; then
        echo "Waiting ${DELAY}s before next task..."
        sleep "$DELAY"
    fi
    echo ""
done

echo "========================================="
echo "All tasks complete!"
echo "Results saved to: $OUTPUT_BASE"
echo "========================================="
