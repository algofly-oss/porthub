// PortHub integration patches to PairDrop v1.11.2 (GPL-3.0).
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const root = process.argv[2] || '/home/node/app';
function load(file, sha) {
  const text = fs.readFileSync(path.join(root,file),'utf8');
  if (crypto.createHash('sha256').update(text).digest('hex') !== sha) throw new Error(`Unexpected upstream PairDrop source: ${file}`);
  return text;
}
function replace(source, before, after) {
  if (!source.includes(before) || source.indexOf(before) !== source.lastIndexOf(before)) throw new Error(`Patch target is not unique: ${before}`);
  return source.replace(before,after);
}
let network = load('public/scripts/network.js','c41b97eb010a2c5ae3e0459237fc3ee659f3f372f75eb3e59f33086365aa77ff');
network = replace(network, "        Events.on('signal', e => this._onMessage(e.detail));", "        Events.on('signal', e => this._onMessage(e.detail));\n        Events.on('porthub-relay-request', e => this._usePortHubRelay(e.detail));");
network = replace(network, '    _onMessage(message) {\n        const peerId = message.sender.id;\n        this.peers[peerId].onServerMessage(message);\n    }', `    _onMessage(message) {
        const peerId = message.sender.id;
        if (!this.peers[peerId]) return;
        if (message.porthubRelay && this._wsConfig.wsFallback) this._usePortHubRelay(peerId, false);
        if (!this.peers[peerId].rtcSupported && (message.sdp || message.ice)) return;
        this.peers[peerId].onServerMessage(message);
    }

    _usePortHubRelay(peerId, notify = true) {
        const peer = this.peers[peerId];
        if (!peer || !peer.rtcSupported || !this._wsConfig.wsFallback) return;
        const roomType = peer._getRoomTypes()[0];
        if (!roomType) return;
        if (peer._channel) { peer._channel.onclose = null; peer._channel.close(); }
        if (peer._conn) { peer._conn.onconnectionstatechange = null; peer._conn.oniceconnectionstatechange = null; peer._conn.close(); }
        const relay = new WSPeer(this._server, false, peerId, roomType, peer._roomIds[roomType]);
        relay._roomIds = {...peer._roomIds};
        this.peers[peerId] = relay;
        Events.fire('porthub-relay-used',peerId);
        if (notify) relay.sendJSON({type:'signal',porthubRelay:true});
    }`);
network = replace(network, '            this.peers[peerId] = new RTCPeer(this._server, isCaller, peerId, roomType, roomId, this._wsConfig.rtcConfig);', `            const peer = new RTCPeer(this._server, isCaller, peerId, roomType, roomId, this._wsConfig.rtcConfig);
            this.peers[peerId] = peer;
            setTimeout(() => { if (this.peers[peerId] === peer && !peer._porthubConnected && !peer._isConnected()) this._usePortHubRelay(peerId); }, 5000);`);
network = replace(network, '    _onConnectionStateChange() {\n        console.log', `    _onConnectionStateChange() {
        if (!this._porthubConnected && ['failed','disconnected'].includes(this._conn.connectionState)) { Events.fire('porthub-relay-request',this._peerId); return; }
        console.log`);
network = replace(network, '    _onChannelOpened(event) {', '    _onChannelOpened(event) {\n        this._porthubConnected = true;');
// Keep error reporting, and recover failed initial ICE negotiation through the
// instance's existing room-authorized, memory-only WebSocket relay.
network = replace(network, '    _onError(error) {\n        console.error(error);\n    }', `    _onError(error) {
        console.error(error);
        if (!this._porthubConnected && this._conn && (this._conn.connectionState === 'failed' || this._conn.iceConnectionState === 'failed')) Events.fire('porthub-relay-request',this._peerId);
    }`);
fs.writeFileSync(path.join(root,'public/scripts/network.js'),network);
let server = load('server/ws-server.js','32b25b3792b76597be1b3672a9ad2e271b794063885c52925dbb7f6bd8348346');
server = replace(server,'new WebSocketServer({ server })','new WebSocketServer({ server, maxPayload: 256 * 1024 })');
server = replace(server,'    _onConnection(peer) {','    _onConnection(peer) {\n        if (this._wss.clients.size > 512) { peer.socket.close(1013, "PairDrop is full"); return; }');
fs.writeFileSync(path.join(root,'server/ws-server.js'),server);
let html = load('public/index.html','fdd39da6f07830c56bbd3bb560cbc83db2245f74346bfb452f475406306ea5f6');
html = replace(html,'</head>','<script src="scripts/porthub.js"></script>\n</head>');
fs.writeFileSync(path.join(root,'public/index.html'),html);
fs.copyFileSync(path.join(root,'LICENSE'),path.join(root,'public/PAIRDrop-LICENSE.txt'));
let ui = load('public/scripts/ui.js','0098cfd460433724b4097d2d6ea719d4bc27dae52a4880da7ed02c926d9f3e5e');
ui = replace(ui,'title="${title}"','title="${window.porthubEscapeText(title)}"');
ui = replace(ui,'${roomSecretsEntry.display_name}','${window.porthubEscapeText(roomSecretsEntry.display_name)}');
ui = replace(ui,'${roomSecretsEntry.device_name}','${window.porthubEscapeText(roomSecretsEntry.device_name)}');
ui = replace(ui, "        Events.on('peer-connected', e => this._onPeerConnected(e.detail.peerId, e.detail.connectionHash));", "        Events.on('peer-connected', e => this._onPeerConnected(e.detail.peerId, e.detail.connectionHash));\n        Events.on('porthub-relay-used', e => { const peer = this.peers[e.detail]; if (peer) peer.rtcSupported = false; const node = $(e.detail); if (node) node.classList.add('ws-peer'); });");
fs.writeFileSync(path.join(root,'public/scripts/ui.js'),ui);
