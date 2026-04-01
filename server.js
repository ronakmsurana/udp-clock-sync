const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { spawn, exec } = require('child_process'); // <-- Added exec
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Serve the frontend HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Handle WebSocket connections from the browser
io.on('connection', (socket) => {
    console.log('Frontend dashboard connected.');

    // Listen for the button click to start the stress test
    socket.on('start_stress_test', () => {
        console.log('Initiating concurrent stress test...');
        
        // Execute the bash script
        exec('./run_test.sh', (error, stdout, stderr) => {
            if (error) {
                console.error(`Exec error: ${error}`);
                socket.emit('stress_result', { status: 'error', data: error.message });
                return;
            }
            // Send the terminal output back to the frontend
            socket.emit('stress_result', { status: 'success', data: stdout });
        });
    });
});

// Start the Web Server
let PORT = 3000;

// Listen for errors (like port already in use)
server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        console.log(`⚠️ Port ${PORT} is busy, trying port ${PORT + 1}...`);
        PORT++; // Increment the port number
        server.listen(PORT); // Try listening again
    } else {
        console.error('Server error:', e);
    }
});

server.listen(PORT, () => {
    console.log(`🚀 Dashboard running at http://localhost:${PORT}`);
    console.log('Spawning C DTLS Client in the background...');

    const dtlsClient = spawn('./dtls_client');

    dtlsClient.stdout.on('data', (data) => {
        const output = data.toString();
        const lines = output.split('\n');
        
        lines.forEach(line => {
            if (line.startsWith('{') && line.endsWith('}')) {
                try {
                    const syncData = JSON.parse(line);
                    io.emit('sync_update', syncData);
                } catch (err) {}
            } else if (line.trim().length > 0) {
                console.log(`[C Client]: ${line.trim()}`);
            }
        });
    });

    dtlsClient.stderr.on('data', (data) => {
        console.error(`[C Client Error]: ${data.toString()}`);
    });
});