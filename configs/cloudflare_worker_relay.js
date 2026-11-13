// Cloudflare Worker WebSocket Relay for FGXP Protocol
// Accepts WebSocket connections from FGXP clients and relays binary
// frames to/from the VPS FGXP server over raw TCP using cloudflare:sockets.
//
// Architecture:
//   Client --[WebSocket over TLS 1.3]--> This Worker --[raw TCP]--> VPS FGXP Server
//
// The ISP transparent proxy sees a standard HTTPS connection to Cloudflare
// (a whitelisted CDN), so the traffic passes through freely even on
// zero-balance mobile data networks.

import { connect } from 'cloudflare:sockets';

function parseHostPort(addr, defaultPort = 443) {
  const trimmed = String(addr || '').trim();
  const lastColon = trimmed.lastIndexOf(':');
  const lastBracket = trimmed.lastIndexOf(']');
  let host = trimmed;
  let port = defaultPort;

  if (lastColon > lastBracket) {
    host = trimmed.slice(0, lastColon);
    const parsedPort = parseInt(trimmed.slice(lastColon + 1), 10);
    if (!Number.isNaN(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
      port = parsedPort;
    }
  }
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }
  return { hostname: host, port };
}

function decoyResponse() {
  return new Response(
    '<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head>' +
    '<body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>',
    { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();

    // Camouflage: standard browser requests or mismatched secret paths get a 200 decoy page
    if (upgradeHeader !== 'websocket') {
      return decoyResponse();
    }
    if (env.WS_PATH && url.pathname !== env.WS_PATH) {
      return decoyResponse();
    }

    // Connect to backend FGXP VPS server via raw TCP before accepting WebSocket
    const targetVPS = env.TARGET_VPS_ADDR || '34.139.64.35:443';
    const { hostname, port } = parseHostPort(targetVPS, 443);

    let tcpSocket;
    try {
      tcpSocket = connect({ hostname, port });
      await tcpSocket.opened;
    } catch (err) {
      try { tcpSocket?.close(); } catch (_) {}
      return new Response('Backend TCP connect failed', { status: 502 });
    }

    // Accept WebSocket upgrade only after backend TCP connection is established
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    const writer = tcpSocket.writable.getWriter();
    const encoder = new TextEncoder();
    let writeChain = Promise.resolve();
    let closed = false;

    const closeBoth = (code = 1000, reason = 'Closed') => {
      if (closed) return;
      closed = true;
      try { writer.releaseLock(); } catch (_) {}
      try { tcpSocket.close(); } catch (_) {}
      try { server.close(code, reason); } catch (_) {}
    };

    // Relay: WebSocket binary messages --> TCP socket (single writer, serialized queue)
    server.addEventListener('message', (event) => {
      let chunk;
      if (event.data instanceof ArrayBuffer) {
        chunk = new Uint8Array(event.data);
      } else if (ArrayBuffer.isView(event.data)) {
        chunk = new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
      } else if (typeof event.data === 'string') {
        chunk = encoder.encode(event.data);
      } else {
        return;
      }

      writeChain = writeChain
        .then(() => writer.write(chunk))
        .catch(() => closeBoth(1011, 'TCP write failed'));
    });

    // Relay: TCP socket --> WebSocket binary messages
    ctx.waitUntil(
      (async () => {
        try {
          const reader = tcpSocket.readable.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value && value.byteLength > 0) {
              const payload =
                value.byteOffset === 0 && value.byteLength === value.buffer.byteLength
                  ? value.buffer
                  : value.slice().buffer;
              server.send(payload);
            }
          }
        } catch (_) {
          // TCP read error - close WebSocket cleanly below
        }
        closeBoth(1000, 'Backend closed');
      })()
    );

    // Clean up TCP on WebSocket close or error
    server.addEventListener('close', () => {
      closeBoth(1000, 'Client closed');
    });

    server.addEventListener('error', () => {
      closeBoth(1011, 'WebSocket error');
    });

    return new Response(null, { status: 101, webSocket: client });
  }
};
