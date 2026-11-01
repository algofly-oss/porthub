const assert = require('node:assert/strict');
const { launchBrowser } = require('./browser.cjs');

(async () => {
  const browser = await launchBrowser();
  try {
    const context = await browser.newContext();
    await context.addInitScript(() => {
      const inputEpoch = 'a'.repeat(32), outputEpoch = 'b'.repeat(32);
      const state = window.__transport = { direct: 0, relay: 0, applied: '', committed: 0, outputAck: 0, duplicates: 0, dropAck: false };
      let socket, channel, outputSequence = 0;
      const packet = (kind, epoch, sequence, payload = new Uint8Array()) => {
        const bytes = new Uint8Array(25 + payload.length); bytes[0] = kind;
        for (let i = 0; i < 16; i++) bytes[i + 1] = parseInt(epoch.slice(i * 2, i * 2 + 2), 16);
        new DataView(bytes.buffer).setBigUint64(17, BigInt(sequence)); bytes.set(payload, 25); return bytes;
      };
      const base64 = bytes => btoa(String.fromCharCode(...bytes));
      const relay = bytes => socket.onmessage?.({ data: JSON.stringify({ type: 'delivery', packet: base64(bytes) }) });
      const receive = (bytes, direct) => {
        const sequence = Number(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(17));
        if (bytes[0] === 2) { state.outputAck = Math.max(state.outputAck, sequence); return; }
        if (direct) state.direct++; else state.relay++;
        if (sequence <= state.committed) state.duplicates++;
        else {
          if (sequence !== state.committed + 1) throw Error('out of order shell input');
          state.applied += new TextDecoder().decode(bytes.slice(25)); state.committed = sequence;
          const output = packet(1, outputEpoch, ++outputSequence, bytes.slice(25));
          setTimeout(() => direct ? channel.onmessage?.({ data: output.buffer }) : relay(output), 0);
        }
        if (!(direct && state.dropAck)) {
          const ack = packet(2, inputEpoch, state.committed);
          setTimeout(() => direct ? channel.onmessage?.({ data: ack.buffer }) : relay(ack), 0);
        }
      };
      window.RTCPeerConnection = class {
        iceGatheringState = 'complete';
        localDescription = { toJSON: () => ({ type: 'offer', sdp: 'v=0\r\n' }) };
        createDataChannel() { return channel = { readyState: 'open', bufferedAmount: 0, send: bytes => receive(bytes, true) }; }
        async createOffer() { return {}; }
        async setLocalDescription() {}
        async setRemoteDescription() { setTimeout(() => { state.ready = true; channel.onopen?.(); }, 0); }
        close() {}
      };
      window.WebSocket = class {
        static OPEN = 1;
        readyState = 0; bufferedAmount = 0;
        constructor() { socket = this; setTimeout(() => { this.readyState = 1; this.onopen?.(); }, 0); }
        send(text) {
          const event = JSON.parse(text);
          if (event.token) this.onmessage?.({ data: JSON.stringify({ type: 'welcome', name: 'transportfixture', read_only: false, participants: 1, expires_at: 0, direct_transport: true }) });
          else if (event.type === 'direct_offer') setTimeout(() => this.onmessage?.({ data: JSON.stringify({ type: 'direct_answer', answer: {
            request: event.request, input_epoch: inputEpoch, output_epoch: outputEpoch, description: JSON.stringify({ type: 'answer', sdp: 'v=0\r\n' }),
          } }) }), 0);
          else if (event.type === 'delivery') receive(Uint8Array.from(atob(event.packet), byte => byte.charCodeAt(0)), false);
        }
        close() { if (this.readyState === 3) return; this.readyState = 3; this.onclose?.(); }
      };
    });
    const page = await context.newPage(), errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`${process.env.REVIEW_ORIGIN || 'http://127.0.0.1:3107'}/terminal#${'c'.repeat(64)}`);
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
    await page.waitForFunction(() => window.__transport.ready);
    await page.locator('.xterm-helper-textarea').focus(); await page.keyboard.type('first');
    await page.waitForFunction(() => window.__transport.applied === 'first' && window.__transport.outputAck > 0);
    await page.evaluate(() => { window.__transport.dropAck = true; });
    await page.keyboard.type('second');
    await page.waitForFunction(() => window.__transport.relay > 0 && window.__transport.duplicates > 0);
    const state = await page.evaluate(() => window.__transport);
    assert.equal(state.applied, 'firstsecond', 'direct-to-relay replay must never repeat text');
    assert(state.direct > 0 && state.relay > 0 && state.outputAck > 0);
    await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
    await page.getByRole('button', { name: 'Reconnect', exact: true }).waitFor();
    assert.deepEqual(errors, []);
    console.log('PASS terminal UI: negotiated direct input, renderer ACKs, stalled ACK relay fallback, no repeated input and explicit disconnect');
    await context.close();
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
