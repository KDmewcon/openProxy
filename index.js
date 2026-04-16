"use strict";

const net = require("net");
const ProxyChain = require("proxy-chain");

function toPort(rawValue, fallback) {
  const value = Number(rawValue);
  if (Number.isInteger(value) && value > 0 && value <= 65535) {
    return value;
  }
  return fallback;
}

const HTTP_PORT = toPort(process.env.HTTP_PORT || process.env.PORT, 2003);
const SOCKS4_PORT = toPort(process.env.SOCKS4_PORT, 2004);
const SOCKS5_PORT = toPort(process.env.SOCKS5_PORT, 2005);
const USERNAME = process.env.PROXY_USER || "tk";
const PASSWORD = process.env.PROXY_PASS || "hehe";

function getSocketClient(socket) {
  return `${socket.remoteAddress || "unknown"}:${socket.remotePort || "?"}`;
}

function logClient(protocol, client, detail) {
  const suffix = detail ? ` ${detail}` : "";
  console.log(`[${new Date().toISOString()}] ${protocol} ${client}${suffix}`);
}

function logSocketClient(protocol, socket, detail) {
  logClient(protocol, getSocketClient(socket), detail);
}

class SocketReader {
  constructor(socket, initialBuffer = Buffer.alloc(0)) {
    this.socket = socket;
    this.buffer = initialBuffer;
    this.ended = false;
    this.error = null;
    this.waiters = [];

    this.onData = (chunk) => {
      if (!chunk || !chunk.length) return;
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.flush();
    };

    this.onEnd = () => {
      this.ended = true;
      this.flush();
    };

    this.onError = (err) => {
      this.error = err;
      this.flush();
    };

    socket.on("data", this.onData);
    socket.on("end", this.onEnd);
    socket.on("close", this.onEnd);
    socket.on("error", this.onError);
  }

  flush() {
    if (!this.waiters.length) return;
    const pending = this.waiters.splice(0);
    for (const resolve of pending) resolve();
  }

  async waitForData() {
    if (this.buffer.length || this.ended || this.error) return;
    await new Promise((resolve) => this.waiters.push(resolve));
  }

  async readBytes(size) {
    while (this.buffer.length < size) {
      if (this.error) throw this.error;
      if (this.ended) return null;
      await this.waitForData();
    }

    const out = this.buffer.subarray(0, size);
    this.buffer = this.buffer.subarray(size);
    return out;
  }

  async readNullTerminated(maxLen = 1024) {
    while (true) {
      const idx = this.buffer.indexOf(0x00);
      if (idx !== -1) {
        const out = this.buffer.subarray(0, idx);
        this.buffer = this.buffer.subarray(idx + 1);
        return out;
      }

      if (this.buffer.length >= maxLen) {
        throw new Error("Null-terminated field too long");
      }

      if (this.error) throw this.error;
      if (this.ended) return null;

      await this.waitForData();
    }
  }

  takeBuffered() {
    const out = this.buffer;
    this.buffer = Buffer.alloc(0);
    return out;
  }

  release() {
    this.socket.off("data", this.onData);
    this.socket.off("end", this.onEnd);
    this.socket.off("close", this.onEnd);
    this.socket.off("error", this.onError);
    this.waiters = [];
  }
}

function createPipeBetween(client, upstream) {
  client.pipe(upstream);
  upstream.pipe(client);

  const closeBoth = () => {
    client.destroy();
    upstream.destroy();
  };

  client.on("error", closeBoth);
  upstream.on("error", closeBoth);
}

function connectTcp(host, port, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const upstream = net.connect({ host, port });

    const cleanup = () => {
      upstream.off("connect", onConnect);
      upstream.off("error", onError);
      upstream.off("timeout", onTimeout);
      upstream.setTimeout(0);
    };

    const onConnect = () => {
      cleanup();
      resolve(upstream);
    };

    const onError = (err) => {
      cleanup();
      reject(err);
    };

    const onTimeout = () => {
      cleanup();
      upstream.destroy();
      reject(new Error("connect timeout"));
    };

    upstream.once("connect", onConnect);
    upstream.once("error", onError);
    upstream.setTimeout(timeoutMs, onTimeout);
  });
}

function sendSocks4Reply(socket, status) {
  // 8-byte response: VN=0x00, CD=status, followed by ignored bind addr/port.
  socket.write(Buffer.from([0x00, status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
}

function sendSocks5Reply(socket, status) {
  // Reply with IPv4 0.0.0.0:0 as bind address.
  socket.write(Buffer.from([0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
}

async function handleSocks4(socket, firstChunk) {
  const client = getSocketClient(socket);
  const reader = new SocketReader(socket, firstChunk.subarray(1));

  try {
    const head = await reader.readBytes(7);
    if (!head) return socket.destroy();

    const command = head[0];
    const port = head.readUInt16BE(1);
    const ip = head.subarray(3, 7);

    const userIdRaw = await reader.readNullTerminated();
    if (!userIdRaw) return socket.destroy();

    const userId = userIdRaw.toString("utf8");
    if (userId !== USERNAME) {
      logClient("SOCKS4", client, `auth failed user=${userId || "(empty)"}`);
      sendSocks4Reply(socket, 0x5b);
      return socket.end();
    }

    if (command !== 0x01) {
      sendSocks4Reply(socket, 0x5b);
      return socket.end();
    }

    let host;
    const isSocks4a = ip[0] === 0 && ip[1] === 0 && ip[2] === 0 && ip[3] !== 0;
    if (isSocks4a) {
      const domainRaw = await reader.readNullTerminated();
      if (!domainRaw || !domainRaw.length) {
        sendSocks4Reply(socket, 0x5b);
        return socket.end();
      }
      host = domainRaw.toString("utf8");
    } else {
      host = `${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}`;
    }

    logClient("SOCKS4", client, `connect ${host}:${port}`);

    let upstream;
    try {
      upstream = await connectTcp(host, port);
    } catch {
      sendSocks4Reply(socket, 0x5b);
      return socket.end();
    }

    sendSocks4Reply(socket, 0x5a);

    const buffered = reader.takeBuffered();
    reader.release();
    if (buffered.length) {
      upstream.write(buffered);
    }

    createPipeBetween(socket, upstream);
  } catch {
    reader.release();
    socket.destroy();
  }
}

async function handleSocks5(socket, firstChunk) {
  const client = getSocketClient(socket);
  const reader = new SocketReader(socket, firstChunk.subarray(1));

  try {
    const nMethodsRaw = await reader.readBytes(1);
    if (!nMethodsRaw) return socket.destroy();

    const nMethods = nMethodsRaw[0];
    const methods = await reader.readBytes(nMethods);
    if (!methods) return socket.destroy();

    if (!methods.includes(0x02)) {
      socket.write(Buffer.from([0x05, 0xff]));
      return socket.end();
    }

    socket.write(Buffer.from([0x05, 0x02]));

    const authVersionAndLen = await reader.readBytes(2);
    if (!authVersionAndLen) return socket.destroy();

    const authVersion = authVersionAndLen[0];
    const unameLen = authVersionAndLen[1];
    if (authVersion !== 0x01) {
      socket.write(Buffer.from([0x01, 0x01]));
      return socket.end();
    }

    const unameRaw = await reader.readBytes(unameLen);
    if (!unameRaw) return socket.destroy();

    const passLenRaw = await reader.readBytes(1);
    if (!passLenRaw) return socket.destroy();

    const passLen = passLenRaw[0];
    const passRaw = await reader.readBytes(passLen);
    if (!passRaw) return socket.destroy();

    const username = unameRaw.toString("utf8");
    const password = passRaw.toString("utf8");

    if (username !== USERNAME || password !== PASSWORD) {
      logClient("SOCKS5", client, `auth failed user=${username || "(empty)"}`);
      socket.write(Buffer.from([0x01, 0x01]));
      return socket.end();
    }

    socket.write(Buffer.from([0x01, 0x00]));

    const requestHead = await reader.readBytes(4);
    if (!requestHead) return socket.destroy();

    const version = requestHead[0];
    const command = requestHead[1];
    const addrType = requestHead[3];

    if (version !== 0x05 || command !== 0x01) {
      sendSocks5Reply(socket, 0x07);
      return socket.end();
    }

    let host;
    if (addrType === 0x01) {
      const ipv4 = await reader.readBytes(4);
      if (!ipv4) return socket.destroy();
      host = `${ipv4[0]}.${ipv4[1]}.${ipv4[2]}.${ipv4[3]}`;
    } else if (addrType === 0x03) {
      const domainLenRaw = await reader.readBytes(1);
      if (!domainLenRaw) return socket.destroy();

      const domainRaw = await reader.readBytes(domainLenRaw[0]);
      if (!domainRaw || !domainRaw.length) return socket.destroy();
      host = domainRaw.toString("utf8");
    } else if (addrType === 0x04) {
      const ipv6Raw = await reader.readBytes(16);
      if (!ipv6Raw) return socket.destroy();
      // Use canonical colon-separated bytes; DNS not needed for outbound connect.
      const groups = [];
      for (let i = 0; i < 16; i += 2) {
        groups.push(ipv6Raw.readUInt16BE(i).toString(16));
      }
      host = groups.join(":");
    } else {
      sendSocks5Reply(socket, 0x08);
      return socket.end();
    }

    const portRaw = await reader.readBytes(2);
    if (!portRaw) return socket.destroy();
    const port = portRaw.readUInt16BE(0);

    logClient("SOCKS5", client, `connect ${host}:${port}`);

    let upstream;
    try {
      upstream = await connectTcp(host, port);
    } catch {
      sendSocks5Reply(socket, 0x05);
      return socket.end();
    }

    sendSocks5Reply(socket, 0x00);

    const buffered = reader.takeBuffered();
    reader.release();
    if (buffered.length) {
      upstream.write(buffered);
    }

    createPipeBetween(socket, upstream);
  } catch {
    reader.release();
    socket.destroy();
  }
}

const httpProxyServer = new ProxyChain.Server({
  port: HTTP_PORT,
  verbose: false,
  prepareRequestFunction: ({ request, username, password, hostname, port, isHttp }) => {
    const client = request && request.socket ? getSocketClient(request.socket) : "unknown:?";
    const requestTarget = request && request.url ? request.url : "(empty)";
    const protocol = isHttp ? "HTTP" : "HTTP-CONNECT";

    logClient(protocol, client, requestTarget);

    if (username !== USERNAME || password !== PASSWORD) {
      logClient(protocol, client, `auth failed user=${username || "(empty)"}`);
      return {
        requestAuthentication: true,
        failMsg: "Proxy authentication required"
      };
    }

    if (!isHttp) {
      const targetHost = hostname || "unknown";
      const targetPort = port || 443;
      logClient("HTTP-CONNECT", client, `established ${targetHost}:${targetPort}`);
    }

    return {};
  }
});

httpProxyServer.on("error", (err) => {
  console.error("HTTP proxy error:", err.message);
});

httpProxyServer.on("requestFailed", ({ request, error }) => {
  const client = request && request.socket ? getSocketClient(request.socket) : "unknown:?";
  logClient("HTTP", client, `request failed ${error ? error.message : "unknown"}`);
});

const socks4Server = net.createServer((socket) => {
  logSocketClient("SOCKS4", socket, "tcp connected");

  socket.once("data", (firstChunk) => {
    if (!firstChunk || !firstChunk.length) {
      return socket.destroy();
    }

    if (firstChunk[0] !== 0x04) {
      logSocketClient("SOCKS4", socket, `invalid version=0x${firstChunk[0].toString(16)}`);
      return socket.destroy();
    }

    handleSocks4(socket, firstChunk);
  });

  socket.on("error", () => {
    // Prevent unhandled socket errors from crashing the process.
  });
});

const socks5Server = net.createServer((socket) => {
  logSocketClient("SOCKS5", socket, "tcp connected");

  socket.once("data", (firstChunk) => {
    if (!firstChunk || !firstChunk.length) {
      return socket.destroy();
    }

    if (firstChunk[0] !== 0x05) {
      logSocketClient("SOCKS5", socket, `invalid version=0x${firstChunk[0].toString(16)}`);
      return socket.destroy();
    }

    handleSocks5(socket, firstChunk);
  });

  socket.on("error", () => {
    // Prevent unhandled socket errors from crashing the process.
  });
});

socks4Server.on("error", (err) => {
  console.error("SOCKS4 server error:", err.message);
});

socks5Server.on("error", (err) => {
  console.error("SOCKS5 server error:", err.message);
});

httpProxyServer.listen(() => {
  console.log(`HTTP proxy running on 0.0.0.0:${HTTP_PORT}`);
});

socks4Server.listen(SOCKS4_PORT, () => {
  console.log(`SOCKS4 proxy running on 0.0.0.0:${SOCKS4_PORT}`);
});

socks5Server.listen(SOCKS5_PORT, () => {
  console.log(`SOCKS5 proxy running on 0.0.0.0:${SOCKS5_PORT}`);
  console.log(`Auth: ${USERNAME} / ${PASSWORD}`);
});
