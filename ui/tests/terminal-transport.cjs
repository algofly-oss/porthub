const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

(async () => {
  const moduleUrl = file => `data:text/javascript;base64,${Buffer.from(file).toString('base64')}`;
  const deliveryUrl = moduleUrl(readFileSync(join(__dirname, '../src/lib/terminalDelivery.js')));
  const { encodePacket, parsePacket } = await import(deliveryUrl);
  const source = readFileSync(join(__dirname, '../src/lib/terminalTransport.js'), 'utf8')
    .replace('"./terminalDelivery"', JSON.stringify(deliveryUrl));
  const { TerminalTransport } = await import(moduleUrl(source));
  const inputEpoch = 'a'.repeat(32), outputEpoch = 'b'.repeat(32);
  const decode = event => parsePacket(Uint8Array.from(Buffer.from(event.packet, 'base64')));
  const answer = { type: 'direct_answer', answer: { request: 1, input_epoch: inputEpoch,
    output_epoch: outputEpoch, description: JSON.stringify({ type: 'answer', sdp: 'v=0' }) } };
  const packets = [], direct = [], failures = [], rendered = [];
  let release;
  const channel = { readyState: 'open', bufferedAmount: 0, send: bytes => direct.push(bytes) };
  const peer = { iceGatheringState: 'complete', createDataChannel: () => channel,
    createOffer: async () => ({}), setLocalDescription: async () => {},
    setRemoteDescription: async () => {}, localDescription: { toJSON: () => ({ type: 'offer', sdp: 'v=0' }) }, close() {} };
  const transport = new TerminalTransport({ send: packet => packets.push(packet),
    write: bytes => { rendered.push(bytes); return new Promise(resolve => release = resolve); },
    fail: reason => failures.push(reason), readOnly: false, createPeer: () => peer });
  const keys = new Uint8Array([101, 99, 104, 111, 13]);
  transport.input(keys);
  assert.equal(packets.pop().type, 'input');
  await transport.start();
  assert.equal(packets.pop().type, 'direct_offer');
  // Tiny keystrokes are coalesced while negotiating, rather than exceeding the
  // 256-frame journal when they are flushed after the answer.
  for (let i = 0; i < 300; i++) transport.input(new Uint8Array([120]));
  assert.equal(packets.length, 0);
  transport.event(answer);
  const initial = packets.pop(); assert.equal(decode(initial).payload.length, 300);
  channel.onopen();
  assert.deepEqual(direct.pop(), Uint8Array.from(Buffer.from(initial.packet, 'base64')));
  channel.onmessage({ data: encodePacket({ kind: 'ack', epoch: inputEpoch, sequence: 1 }).buffer });
  assert.equal(transport.inputJournal.pendingFrames, 0);
  const output = encodePacket({ kind: 'data', epoch: outputEpoch, sequence: 1, payload: keys });
  channel.onmessage({ data: output.buffer });
  assert.equal(rendered.length, 1);
  assert.equal(direct.length, 0, 'network receipt must not acknowledge unrendered bytes');
  transport.event({ type: 'delivery', packet: Buffer.from(output).toString('base64') });
  assert.equal(rendered.length, 1, 'relay replay cannot render the same pending frame twice');
  release(); await Promise.resolve(); await Promise.resolve();
  assert.equal(decode(packets.pop()).sequence, 1);
  transport.input(keys);
  const command = packets.pop();
  transport.fallback();
  const replay = packets.find(event => event.type === 'delivery' && decode(event).kind === 'data');
  assert.equal(replay.packet, command.packet, 'path replay retains the original input sequence');
  packets.length = 0;
  transport.event({ type: 'delivery', packet: Buffer.from(encodePacket({ kind: 'ack', epoch: inputEpoch, sequence: 2 })).toString('base64') });
  transport.fallback();
  assert(!packets.some(event => decode(event).kind === 'data'));
  for (let i = 0; i < 4; i++) transport.input(new Uint8Array(16384));
  const before = packets.length;
  assert.throws(() => transport.input(keys));
  assert.equal(packets.length, before, 'a full journal must reject the entire next paste');
  assert.throws(() => transport.event(answer), /Unexpected/);
  transport.close();
  assert.equal(failures.length, 0);
  const legacy = [];
  const unavailable = new TerminalTransport({ send: event => legacy.push(event), write: async () => {},
    fail: reason => failures.push(reason), readOnly: false, createPeer: () => peer });
  await unavailable.start(); unavailable.input(keys);
  unavailable.event({ type: 'direct_unavailable', request: 1 });
  assert.equal(legacy.pop().type, 'input'); unavailable.close();
  const reader = new TerminalTransport({ send: () => {}, write: async () => {}, fail: () => {}, readOnly: true });
  assert.throws(() => reader.input(keys)); reader.close();
  console.log('PASS browser transport: negotiation, render ACKs, replay deduplication, atomic backpressure and legacy fallback');
})().catch(error => { console.error(error); process.exitCode = 1; });
