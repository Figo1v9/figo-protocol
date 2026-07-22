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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Camouflage: standard browser requests get a normal-looking page
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response(
        '<!DOCTYPE html><html><head><title>Cloud Service</title></head>' +
        '<body><h1>Service Online</h1><p>Status: OK</p></body></html>',
        { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } }
      );
    }

    // Handle WebSocket upgrade
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    // Connect to backend FGXP VPS server via raw TCP
    const targetVPS = env.TARGET_VPS_ADDR || "34.139.64.35:80";
    const [host, portStr] = targetVPS.split(":");
    const port = parseInt(portStr || "80", 10);

    let tcpSocket;
    try {
      tcpSocket = connect({ hostname: host, port: port });
    } catch (err) {
      server.close(1011, "Backend connection failed");
      return new Response(null, { status: 101, webSocket: client });
    }

    // Relay: WebSocket binary messages --> TCP socket
    server.addEventListener("message", async (event) => {
      try {
        const writer = tcpSocket.writable.getWriter();
        if (event.data instanceof ArrayBuffer) {
          await writer.write(new Uint8Array(event.data));
        } else if (typeof event.data === "string") {
          await writer.write(new TextEncoder().encode(event.data));
        }
        writer.releaseLock();
      } catch (err) {
        server.close(1011, "TCP write failed");
      }
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
              server.send(value.buffer);
            }
          }
        } catch (err) {
          // TCP read error - close WebSocket
        }
        try { server.close(1000, "Backend closed"); } catch (e) {}
      })()
    );

    // Clean up TCP on WebSocket close
    server.addEventListener("close", () => {
      try { tcpSocket.close(); } catch (e) {}
    });

    server.addEventListener("error", () => {
      try { tcpSocket.close(); } catch (e) {}
    });

    return new Response(null, { status: 101, webSocket: client });
  }
};
