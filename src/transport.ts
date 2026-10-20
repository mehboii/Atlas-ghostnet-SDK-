import { ConnectionError } from './errors.js';
import { Logger } from './logger.js';
import { endpointOrigin } from './endpoint.js';

const DEFAULT_RECONNECT_BASE_MS = 1000;
const DEFAULT_RECONNECT_MAX_MS = 30_000;
const DEFAULT_RECONNECT_FACTOR = 2;
const MAX_RECONNECT_ATTEMPTS = 10;

/**
 * WebSocket `readyState` value for an open connection (per the WHATWG spec).
 * Referenced as a literal instead of `WebSocket.OPEN` because the global
 * `WebSocket` is not defined on Node.js < 22, where we fall back to the
 * `ws` package — reading `WebSocket.OPEN` there would throw a ReferenceError.
 */
const WEBSOCKET_OPEN = 1;

export interface TransportEvents {
  open: () => void;
  close: (reason: string) => void;
  message: (data: Uint8Array | string) => void;
  error: (err: Error) => void;
}

type EventName = keyof TransportEvents;

/**
 * WebSocket wrapper with automatic reconnect and exponential backoff.
 *
 * Works with both the browser `WebSocket` global and the `ws` npm package
 * in Node.js. Detection is automatic — no configuration needed.
 *
 * @example
 * ```ts
 * const transport = new Transport('wss://relay.ghostnet.dev', logger);
 * transport.on('message', (data) => console.log(data));
 * await transport.connect();
 * ```
 */
export class Transport {
  private url: string;
  private logger: Logger;
  private ws: WebSocket | null = null;
  private listeners: { [K in EventName]: Set<TransportEvents[K]> } = {
    open: new Set(),
    close: new Set(),
    message: new Set(),
    error: new Set(),
  };
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionalClose = false;
  private everConnected = false;

  constructor(url: string, logger: Logger) {
    this.url = url;
    this.logger = logger;
  }

  /**
   * Register an event listener.
   *
   * @example
   * ```ts
   * transport.on('open', () => console.log('connected'));
   * ```
   */
  on<K extends EventName>(event: K, handler: TransportEvents[K]): void {
    this.listeners[event].add(handler);
  }

  /**
   * Remove an event listener.
   *
   * @example
   * ```ts
   * transport.off('open', myHandler);
   * ```
   */
  off<K extends EventName>(event: K, handler: TransportEvents[K]): void {
    this.listeners[event].delete(handler);
  }

  /**
   * Open the WebSocket connection. Resolves when the socket is open,
   * rejects if the initial connection fails.
   *
   * @example
   * ```ts
   * await transport.connect();
   * ```
   */
  async connect(): Promise<void> {
    this.intentionalClose = false;
    return this.createSocket();
  }

  /**
   * Gracefully close the WebSocket. Disables reconnect.
   *
   * @example
   * ```ts
   * transport.disconnect();
   * ```
   */
  disconnect(): void {
    this.intentionalClose = true;
    this.clearReconnectTimer();
    if (this.ws) {
      this.ws.close(1000, 'client disconnect');
      this.ws = null;
    }
  }

  /**
   * Send raw data over the open socket.
   *
   * @throws {ConnectionError} If the socket is not open.
   *
   * @example
   * ```ts
   * transport.send(JSON.stringify({ type: 'msg', payload: '...' }));
   * ```
   */
  send(data: string | Uint8Array): void {
    if (!this.ws || this.ws.readyState !== WEBSOCKET_OPEN) {
      throw new ConnectionError('WebSocket is not connected');
    }
    this.ws.send(data);
  }

  /** Whether the socket is currently open. */
  get connected(): boolean {
    return this.ws?.readyState === WEBSOCKET_OPEN;
  }

  private wsClass: typeof WebSocket | null = typeof globalThis.WebSocket !== 'undefined' ? globalThis.WebSocket : null;

  private async resolveWebSocketClass(): Promise<typeof WebSocket> {
    if (this.wsClass) return this.wsClass;
    if (typeof globalThis.WebSocket !== 'undefined') {
      this.wsClass = globalThis.WebSocket;
      return this.wsClass;
    }
    const wsPkg = 'ws';
    const wsModule = await import(wsPkg);
    this.wsClass = (wsModule.default ?? wsModule) as unknown as typeof WebSocket;
    return this.wsClass;
  }

  private createSocket(): Promise<void> {
    const directWS = typeof globalThis.WebSocket !== 'undefined' ? globalThis.WebSocket : this.wsClass;
    if (directWS) {
      return this.initSocket(directWS);
    }
    return this.resolveWebSocketClass().then((WS) => {
      if (this.intentionalClose) return;
      return this.initSocket(WS);
    });
  }

  private initSocket(WS: typeof WebSocket): Promise<void> {
    return new Promise((resolve, reject) => {
      this.logger.debug(`Connecting to ${endpointOrigin(this.url)}`);

      let ws: WebSocket;
      try {
        ws = new WS(this.url);
      } catch {
        reject(new ConnectionError(`Unable to open WebSocket on ${endpointOrigin(this.url)}`));
        return;
      }
      // Node ws needs binaryType set for Uint8Array
      ws.binaryType = 'arraybuffer';

      // Track the socket from construction so disconnect() can abort a
      // connection that is still in the CONNECTING state. `connected` and
      // `send()` gate on readyState === OPEN, so this is safe before open.
      this.ws = ws;
      let settled = false;

      ws.onopen = () => {
        this.everConnected = true;
        this.reconnectAttempt = 0;
        this.logger.debug('Connected');
        this.emit('open');
        if (!settled) {
          settled = true;
          resolve();
        }
      };

      ws.onclose = (event: CloseEvent) => {
        const reason = event.reason || `code ${event.code}`;
        this.logger.debug(`Disconnected: ${reason}`);
        if (this.ws === ws) {
          this.ws = null;
        }
        this.emit('close', reason);

        // Reject the connect() promise if the socket closed before opening.
        if (!settled) {
          settled = true;
          reject(new ConnectionError(`WebSocket closed before opening: ${reason}`));
        }

        if (!this.intentionalClose && this.everConnected) {
          this.scheduleReconnect();
        }
      };

      ws.onerror = () => {
        const err = new ConnectionError(`WebSocket error on ${endpointOrigin(this.url)}`);
        this.emit('error', err);
        // If the socket never opened, reject the initial connection promise.
        if (!settled) {
          settled = true;
          reject(err);
        }
      };

      ws.onmessage = (event: MessageEvent) => {
        const data = event.data instanceof ArrayBuffer
          ? new Uint8Array(event.data)
          : (event.data as string);
        this.emit('message', data);
      };
    });
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempt >= MAX_RECONNECT_ATTEMPTS) {
      this.logger.error(`Max reconnect attempts (${MAX_RECONNECT_ATTEMPTS}) reached, giving up`);
      this.emit('error', new ConnectionError(
        `Failed to reconnect after ${MAX_RECONNECT_ATTEMPTS} attempts`,
      ));
      return;
    }

    const delay = Math.min(
      DEFAULT_RECONNECT_BASE_MS * (DEFAULT_RECONNECT_FACTOR ** this.reconnectAttempt),
      DEFAULT_RECONNECT_MAX_MS,
    );
    this.reconnectAttempt++;
    this.logger.debug(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempt}/${MAX_RECONNECT_ATTEMPTS})`);

    this.reconnectTimer = setTimeout(() => {
      this.createSocket().catch((err: unknown) => {
        this.logger.warn(`Reconnect failed: ${err instanceof Error ? err.message : String(err)}`);
      });
    }, delay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private emit<K extends EventName>(event: K, ...args: Parameters<TransportEvents[K]>): void {
    for (const handler of this.listeners[event]) {
      (handler as (...a: unknown[]) => void)(...args);
    }
  }
}
