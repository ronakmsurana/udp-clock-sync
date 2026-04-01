#!/bin/bash
echo "Starting Concurrent Server Stress Test..."

# Store the number of clients in a variable
CONCURRENCY_LEVEL=10

# Display the concurrency level
echo "Launching ${CONCURRENCY_LEVEL} concurrent clients..."

# Launch 10 stress clients in the background simultaneously
for i in {1..${CONCURRENCY_LEVEL}}
do
   ./stress_client &
done

# Wait for all background clients to finish
wait
echo "Stress test complete!"