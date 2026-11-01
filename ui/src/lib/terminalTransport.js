import { terminalStunServers } from "./terminalConnectivity.mjs";
import { InputJournal, OutputJournal, MAX_BYTES, MAX_PAYLOAD, parsePacket } from "./terminalDelivery";

const MAX_BUFFERED = 262144;
function base64(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

// Signalling and authorization always use the existing authenticated gateway.
// The caller enables this only for a negotiated, policy-approved attachment.
export class TerminalTransport {
  constructor({ send, write, fail, readOnly, changed = () => {}, createPeer = config => new RTCPeerConnection(config), stunServers = [] }) {
    Object.assign(this, { send, write, fail, readOnly, changed, createPeer });
    this.stunServers = terminalStunServers(stunServers);
    this.closed = false;
    this.offered = false;
    this.answered = false;
    this.relay = true;
    this.queued = [];
    this.queuedBytes = 0;
  }
  input(bytes) {
    if (this.closed || this.readOnly) throw new Error("Terminal input is unavailable");
    if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > MAX_BYTES)
      throw new Error("Terminal input exceeds limit");
    // Reject an entire paste before sending any part, rather than type half a
    // command if the replay journal fills partway through the paste.
    const frames = Math.ceil(bytes.length / MAX_PAYLOAD);
    if (this.offered && !this.answered) {
      if (this.queuedBytes + bytes.length > MAX_BYTES) throw new Error("Terminal negotiation input is full");
      this.queued.push(bytes.slice()); this.queuedBytes += bytes.length;
      return;
    }
    if (this.answered && (this.inputJournal.retainedBytes + bytes.length > MAX_BYTES ||
      this.inputJournal.pendingFrames + frames > 256)) throw new Error("Terminal input is awaiting acknowledgement");
    const packets = [];
    for (let offset = 0; offset < bytes.length; offset += MAX_PAYLOAD) {
      const chunk = bytes.subarray(offset, offset + MAX_PAYLOAD);
      if (!this.answered) this.send({ type: "input", data: base64(chunk) });
      else packets.push(this.inputJournal.enqueue(chunk));
    }
    if (this.answered) {
      this.watchInput();
      // Retain the whole paste before attempting either carrier. A synchronous
      // carrier failure cannot strand its unsent suffix outside the journal.
      for (const packet of packets) this.transmit(packet);
    }
  }
  async start() {
    if (this.closed || this.peer) return;
    try {
      // Only endpoints explicitly chosen in this local browser are contacted.
      const peer = this.peer = this.createPeer({ iceServers: this.stunServers.map(url=>({urls:url})) });
      const channel = this.channel = peer.createDataChannel("porthub-terminal/1", { ordered: true });
      channel.binaryType = "arraybuffer";
      channel.onopen = () => {
        if (this.closed || !this.answered) return;
        this.relay = false; this.changed("direct");
        for (const packet of this.inputJournal.replay()) this.transmit(packet);
      };
      channel.onmessage = event => {
        if (this.closed) return;
        try { this.accept(new Uint8Array(event.data), true); } catch { this.abort("Invalid direct terminal response"); }
      };
      channel.onclose = channel.onerror = () => this.fallback();
      peer.onconnectionstatechange = () => {
        if (["failed", "disconnected", "closed"].includes(peer.connectionState)) this.fallback();
      };
      await peer.setLocalDescription(await peer.createOffer());
      if (peer.iceGatheringState !== "complete") {
        await new Promise((resolve, reject) => {
          this.gatherTimer = setTimeout(() => reject(new Error("Candidate gathering timed out")), 5000);
          this.cancelGather = () => reject(new Error("Terminal transport closed"));
          peer.onicegatheringstatechange = () => { if (peer.iceGatheringState === "complete") resolve(); };
        });
      }
      clearTimeout(this.gatherTimer); this.cancelGather = null;
      if (this.closed) return;
      const description = JSON.stringify(peer.localDescription.toJSON());
      if (description.length > 16384) throw new Error("Terminal offer exceeds limit");
      this.offered = true;
      this.send({ type: "direct_offer", request: 1, description });
      // Once an offer is sent, an unacknowledged answer may mean the host has
      // switched framing. Reconnect rather than guess and repeat shell input.
      this.answerTimer = setTimeout(() => this.abort("Terminal negotiation timed out; reconnect to redraw"), 15000);
    } catch {
      clearTimeout(this.gatherTimer); this.cancelGather = null;
      if (!this.closed && !this.offered) { this.peer?.close(); this.changed("relay"); }
      else if (!this.closed) this.abort("Terminal negotiation failed; reconnect to redraw");
    }
  }
  event(event) {
    if (event.type === "direct_unavailable") {
      if (!this.offered || this.answered || event.request !== 1) throw new Error("Unexpected terminal negotiation reply");
      clearTimeout(this.answerTimer);
      this.offered = false; this.peer?.close(); this.flushQueued(); this.changed("relay");
      return true;
    }
    if (event.type === "direct_answer") {
      const answer = event.answer;
      if (!this.offered || this.answered || answer?.request !== 1 ||
        typeof answer.description !== "string" || answer.description.length > 16384 ||
        answer.input_epoch === answer.output_epoch) throw new Error("Unexpected terminal direct answer");
      const description = JSON.parse(answer.description);
      if (description.type !== "answer" || typeof description.sdp !== "string") throw new Error("Invalid terminal answer");
      this.inputJournal = new InputJournal(answer.input_epoch);
      this.outputJournal = new OutputJournal(answer.output_epoch);
      this.answered = true; clearTimeout(this.answerTimer);
      this.flushQueued();
      Promise.resolve(this.peer.setRemoteDescription(description)).catch(() => this.fallback());
      return true;
    }
    if (event.type === "delivery") {
      if (typeof event.packet !== "string" || event.packet.length > 21880) throw new Error("Invalid terminal relay packet");
      this.accept(Uint8Array.from(atob(event.packet), byte => byte.charCodeAt(0)), false);
      return true;
    }
    return false;
  }
  flushQueued() {
    const queued = this.queued; this.queued = []; this.queuedBytes = 0;
    const combined = new Uint8Array(queued.reduce((size, bytes) => size + bytes.length, 0));
    let offset = 0;
    for (const bytes of queued) { combined.set(bytes, offset); offset += bytes.length; }
    if (combined.length) this.input(combined);
  }
  transmit(packet) {
    if (this.closed) return;
    if (!this.relay && this.channel?.readyState === "open" && this.channel.bufferedAmount <= MAX_BUFFERED) {
      try { this.channel.send(packet); return; } catch { /* Replay the same sequence through the gateway. */ }
    }
    this.relay = true;
    this.send({ type: "delivery", packet: base64(packet) });
  }
  fallback() {
    if (this.closed || !this.answered) return;
    this.relay = true; this.changed("relay");
    try {
      for (const packet of this.inputJournal.replay()) this.transmit(packet);
      this.transmit(this.outputJournal.acknowledgement());
    } catch { this.abort("Terminal gateway unavailable; reconnect to redraw"); }
  }
  watchInput() {
    if (this.closed || this.inputTimer || !this.inputJournal.pendingFrames) return;
    this.inputSince = this.inputSince || Date.now();
    this.inputTimer = setTimeout(() => {
      this.inputTimer = null;
      if (this.closed || !this.inputJournal.pendingFrames) return;
      if (Date.now() - this.inputSince >= 15000) { this.abort("Terminal input acknowledgement timed out; reconnect to redraw"); return; }
      this.fallback(); this.watchInput();
    }, 1000);
  }
  accept(bytes, direct) {
    if (!this.answered) throw new Error("Terminal data arrived before negotiation");
    const packet = parsePacket(bytes);
    if (packet.kind === "ack") {
      this.inputJournal.acknowledge(packet);
      if (packet.sequence > (this.inputAcknowledged || 0)) {
        this.inputAcknowledged = packet.sequence;
        this.inputSince = Date.now();
      }
      if (!this.inputJournal.pendingFrames) { clearTimeout(this.inputTimer); this.inputTimer = null; this.inputSince = null; }
      return;
    }
    if (!direct) { this.relay = true; this.changed("relay"); }
    this.outputJournal.stage(packet);
    if (!this.rendering) this.drain();
  }
  async drain() {
    this.rendering = true;
    try {
      let frame;
      while (!this.closed && (frame = this.outputJournal.next())) {
        await this.write(frame.payload);
        if (this.closed) return;
        this.outputJournal.commit(frame.sequence);
      }
      this.transmit(this.outputJournal.acknowledgement());
    } catch { this.abort("Terminal output could not be accepted; reconnect to redraw"); }
    finally { this.rendering = false; }
  }
  abort(reason) { if (!this.closed) { this.close(); this.fail(reason); } }
  close() {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.gatherTimer); clearTimeout(this.answerTimer); clearTimeout(this.inputTimer);
    this.cancelGather?.(); this.peer?.close();
    this.queued = []; this.queuedBytes = 0;
  }
}
