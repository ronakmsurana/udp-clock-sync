#!/bin/bash
echo "Starting Concurrent Server Stress Test..."

# Launch 10 stress clients in the background simultaneously
for i in {1..10}
do
   ./stress_client &
done

# Wait for all background clients to finish
wait
echo "Stress test complete!"