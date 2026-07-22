// Cloudflare Worker Relay Script for FGXP Protocol (Cloudflare Edge Fronting)
// High-performance streaming relay using Cloudflare Sockets (TCP) & Fetch Streams.

import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // Camouflage response for standard web crawlers on root /
    if (url.pathname === "/" && request.method !== "POST" && request.headers.get("Upgrade") !== "websocket") {
      return new Response("FGXP Edge Camouflage Server Ready", { status: 200 });
    }

    // Connect to backend FGXP VPS server on Port 80 (Plaintext HTTP Framing)
    const targetVPS = env.TARGET_VPS_ADDR || "34.139.64.35:80";
    const [host, portStr] = targetVPS.split(":");
    const port = parseInt(portStr || "80", 10);

    try {
      // Dial backend FGXP VPS server over TCP socket
      const tcpSocket = connect({ hostname: host, port: port });
      const writer = tcpSocket.writable.getWriter();

      // Synthesize L7 HTTP Framing GET request to backend VPS
      const reqHeaders = `GET ${url.pathname}${url.search} HTTP/1.1\r\n` +
        `Host: ${request.headers.get("Host") || host}\r\n` +
        `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0\r\n` +
        `Connection: Upgrade\r\n` +
        `Upgrade: websocket\r\n\r\n`;

      await writer.write(new TextEncoder().encode(reqHeaders));
      writer.releaseLock();

      // Pipe any payload body if present
      if (request.body) {
        request.body.pipeTo(tcpSocket.writable).catch(() => {});
      }

      // Stream VPS TCP Socket -> Client HTTP Response
      return new Response(tcpSocket.readable, {
        status: 200,
        headers: {
          "Content-Type": "application/octet-stream",
          "Cache-Control": "no-cache, no-store",
        },
      });

    } catch (err) {
      return new Response("Backend Dial Failed: " + err.message, { status: 502 });
    }
  }
};
