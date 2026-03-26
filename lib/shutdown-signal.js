// Special signal used to gracefully shut down the fuzzer server
// after all client scenarios have finished.
// This prevents the server from hanging in a "listening" state.

module.exports = {
  // Use a special SNI hostname that is highly unlikely to occur in real traffic
  SHUTDOWN_HOSTNAME: 'fuzzer-shutdown-signal.local',
  
  // Also define a special path for HTTP/2 if needed
  SHUTDOWN_PATH: '/__fuzzer_shutdown__',
};
