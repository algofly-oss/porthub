// Audio stays in memory and is delivered only to the authenticated Rust API.
class PortHubCapture extends AudioWorkletProcessor {
  constructor(){super();this.frames=[];this.length=0;}
  process(inputs){const input=inputs[0]?.[0];if(input?.length){this.frames.push(input.slice());this.length+=input.length;if(this.length>=sampleRate/4){const pcm=new Float32Array(this.length);let at=0;for(const frame of this.frames){pcm.set(frame,at);at+=frame.length;}this.port.postMessage({pcm,rate:sampleRate},[pcm.buffer]);this.frames=[];this.length=0;}}return true;}
}
registerProcessor('porthub-capture',PortHubCapture);
