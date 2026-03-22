const dgram = require('dgram');

const server = dgram.createSocket('udp4');
server.on('message', (msg, rinfo) => {
  console.log(`Server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
  server.send('PONG', rinfo.port, rinfo.address, (err) => {
    if (err) console.error('Server send error:', err);
  });
});
server.bind(4433, '0.0.0.0', () => {
  console.log('Server bound');
  const client = dgram.createSocket('udp4');
  client.on('message', (msg) => {
    console.log(`Client got: ${msg}`);
    server.close();
    client.close();
  });
  client.send('PING', 4433, '127.0.0.1', (err) => {
    if (err) console.error('Client send error:', err);
  });
});
