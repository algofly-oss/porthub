// One attachment's journal, shared by WebRTC and gateway delivery. A fresh
// attachment must create fresh journals; never replay uncertain old shell input.
export const MAX_PAYLOAD = 16384;
export const MAX_BYTES = 65536;
export const MAX_FRAMES = 256;
const HEADER = 25;

function check(condition, message) {
  if (!condition) throw new Error(message);
}
function epochValid(epoch) {
  check(typeof epoch === "string" && /^[a-f0-9]{32}$/.test(epoch), "Invalid terminal epoch");
}
function sequenceValid(sequence, minimum = 0) {
  check(Number.isSafeInteger(sequence) && sequence >= minimum, "Invalid terminal sequence");
}
function payloadValid(payload) {
  check(payload instanceof Uint8Array && payload.length > 0 && payload.length <= MAX_PAYLOAD,
    "Invalid terminal payload");
}

export function encodePacket({ kind, epoch, sequence, payload }) {
  epochValid(epoch);
  sequenceValid(sequence, kind === "data" ? 1 : 0);
  check(kind === "data" || kind === "ack", "Invalid terminal packet kind");
  if (kind === "data") payloadValid(payload);
  else check(payload === undefined, "Terminal acknowledgement contains data");
  const bytes = new Uint8Array(HEADER + (payload?.length || 0));
  bytes[0] = kind === "data" ? 1 : 2;
  for (let i = 0; i < 16; i++) bytes[i + 1] = parseInt(epoch.slice(i * 2, i * 2 + 2), 16);
  new DataView(bytes.buffer).setBigUint64(17, BigInt(sequence));
  if (payload) bytes.set(payload, HEADER);
  return bytes;
}

export function parsePacket(bytes) {
  check(bytes instanceof Uint8Array && bytes.length >= HEADER && bytes.length <= HEADER + MAX_PAYLOAD,
    "Invalid terminal packet size");
  const sequence = Number(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(17));
  sequenceValid(sequence);
  let epoch = "";
  for (const byte of bytes.subarray(1, 17)) epoch += byte.toString(16).padStart(2, "0");
  if (bytes[0] === 2) {
    check(bytes.length === HEADER, "Terminal acknowledgement contains data");
    return { kind: "ack", epoch, sequence };
  }
  check(bytes[0] === 1, "Invalid terminal packet kind");
  sequenceValid(sequence, 1);
  const payload = bytes.slice(HEADER);
  payloadValid(payload);
  return { kind: "data", epoch, sequence, payload };
}

export class InputJournal {
  #epoch;
  #last = 0;
  #pending = new Map();
  #bytes = 0;
  constructor(epoch) { epochValid(epoch); this.#epoch = epoch; }
  get retainedBytes() { return this.#bytes; }
  get pendingFrames() { return this.#pending.size; }
  enqueue(payload) {
    payloadValid(payload);
    check(this.#pending.size < MAX_FRAMES && this.#bytes + payload.length <= MAX_BYTES,
      "Terminal input is awaiting acknowledgement");
    const sequence = this.#last + 1;
    sequenceValid(sequence, 1);
    const packet = { kind: "data", epoch: this.#epoch, sequence, payload: payload.slice() };
    this.#last = sequence;
    this.#pending.set(sequence, packet);
    this.#bytes += payload.length;
    return encodePacket(packet);
  }
  acknowledge({ kind, epoch, sequence }) {
    sequenceValid(sequence);
    check(kind === "ack" && epoch === this.#epoch && sequence <= this.#last,
      "Invalid terminal input acknowledgement");
    for (const [key, packet] of this.#pending) {
      if (key > sequence) break;
      this.#bytes -= packet.payload.length;
      this.#pending.delete(key);
    }
  }
  *replay() {
    for (const packet of this.#pending.values()) yield encodePacket(packet);
  }
}

export class OutputJournal {
  #epoch;
  #committed = 0;
  #pending = new Map();
  #bytes = 0;
  constructor(epoch) { epochValid(epoch); this.#epoch = epoch; }
  get retainedBytes() { return this.#bytes; }
  stage({ kind, epoch, sequence, payload }) {
    sequenceValid(sequence, 1);
    payloadValid(payload);
    check(kind === "data" && epoch === this.#epoch, "Invalid terminal output epoch");
    if (sequence <= this.#committed) return false;
    check(sequence - this.#committed <= MAX_FRAMES, "Terminal output exceeds receive window");
    const previous = this.#pending.get(sequence);
    if (previous) {
      check(previous.length === payload.length && previous.every((byte, i) => byte === payload[i]),
        "Conflicting terminal replay");
      return false;
    }
    check(this.#pending.size < MAX_FRAMES && this.#bytes + payload.length <= MAX_BYTES,
      "Terminal output journal is full");
    this.#pending.set(sequence, payload.slice());
    this.#bytes += payload.length;
    return true;
  }
  next() {
    const sequence = this.#committed + 1, payload = this.#pending.get(sequence);
    return payload ? { sequence, payload: payload.slice() } : null;
  }
  // Call from xterm's write completion callback, rather than on network receipt.
  commit(sequence) {
    sequenceValid(sequence, 1);
    check(sequence === this.#committed + 1 && this.#pending.has(sequence),
      "Terminal output is not ready to commit");
    this.#bytes -= this.#pending.get(sequence).length;
    this.#pending.delete(sequence);
    this.#committed = sequence;
  }
  acknowledgement() {
    return encodePacket({ kind: "ack", epoch: this.#epoch, sequence: this.#committed });
  }
}
