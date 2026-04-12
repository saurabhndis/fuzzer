const net = require('net');

const srv = net.createServer();
srv.listen(4433, () => {
  console.log('Listening');
  
  // Connect before adding listener
  const cli = net.createConnection({ port: 4433, host: 'localhost' });
  cli.on('connect', () => {
    console.log('Client connected');
    
    // Now add listener
    srv.on('connection', (sock) => {
      console.log('Server got connection!');
    });
    
    // Will it fire?
    setTimeout(() => {
      console.log('Finished waiting');
      srv.close();
      cli.destroy();
    }, 1000);
  });
});
