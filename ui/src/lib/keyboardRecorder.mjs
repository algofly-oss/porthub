export function pcm16(frames,rate) {
  const length=frames.reduce((n,f)=>n+f.length,0),all=new Float32Array(length);let at=0;
  for(const frame of frames){all.set(frame,at);at+=frame.length;}
  const output=new ArrayBuffer(Math.floor(length*16000/rate)*2),view=new DataView(output);
  for(let i=0;i<output.byteLength/2;i++){const from=i*rate/16000,to=Math.min(length,(i+1)*rate/16000);let sum=0,weight=0;
    for(let j=Math.floor(from);j<Math.ceil(to);j++){const w=Math.min(j+1,to)-Math.max(j,from);if(w>0){sum+=all[j]*w;weight+=w;}}
    const value=Math.max(-1,Math.min(1,weight?sum/weight:0));view.setInt16(i*2,Math.round(value*(value<0?32768:32767)),true);
  }return output;
}
export class VoiceRecorder {
  constructor({segment,level=()=>{},failed=()=>{}}){Object.assign(this,{segment,level,failed});this.frames=[];this.speech=0;this.silence=0;this.duration=0;this.closed=false;}
  async start(){
    try {
      this.stream=await navigator.mediaDevices.getUserMedia({audio:{channelCount:1,echoCancellation:true,noiseSuppression:true}});
      if(this.closed){this.stream.getTracks().forEach(t=>t.stop());return;}
      const Audio=window.AudioContext||window.webkitAudioContext;this.context=new Audio({sampleRate:16000});await this.context.resume();
      await this.context.audioWorklet.addModule('/keyboard-capture.js');if(this.closed){await this.stop(false);return;}
      this.node=new AudioWorkletNode(this.context,'porthub-capture');this.source=this.context.createMediaStreamSource(this.stream);
      this.mute=this.context.createGain();this.mute.gain.value=0;this.source.connect(this.node).connect(this.mute).connect(this.context.destination);
      this.node.port.onmessage=({data})=>this.accept(data.pcm,data.rate);
      this.stream.getAudioTracks()[0].onended=()=>{if(!this.closed){this.failed('Microphone disconnected');void this.stop();}};
    }catch(error){await this.stop(false);throw error;}
  }
  accept(pcm,rate){if(this.closed)return;this.rate=rate;const rms=Math.sqrt(pcm.reduce((sum,v)=>sum+v*v,0)/pcm.length);this.level(Math.min(1,rms*10));const seconds=pcm.length/rate;
    if(rms>0.012){this.speech+=seconds;this.silence=0;}else this.silence+=seconds;
    // Retain at most 0.5 seconds of leading silence, not endless quiet audio.
    if(!this.speech&&this.frames.length>=2)this.frames.shift();this.frames.push(pcm);this.duration+=seconds;
    if((this.silence>=0.75&&this.speech>=0.25)||this.duration>=12){this.flush();}
  }
  flush(){if(this.speech>=0.25&&this.frames.length){this.segment(pcm16(this.frames,this.rate));}this.frames=[];this.speech=0;this.silence=0;this.duration=0;}
  async stop(flush=true){this.closed=true;if(flush)this.flush();else this.frames=[];if(this.node)this.node.port.onmessage=null;this.node?.disconnect();this.source?.disconnect();this.mute?.disconnect();this.stream?.getTracks().forEach(t=>t.stop());if(this.context?.state!=='closed')await this.context?.close();this.level(0);}
}
