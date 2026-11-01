// STUN is an explicit local choice. No gateway frame populates this list.
export function terminalStunServers(values) {
  const entries = typeof values === "string" ? values.split(/[\s,]+/).filter(Boolean) : values;
  if (!Array.isArray(entries) || entries.length > 2) throw Error("Choose at most two UDP STUN endpoints.");
  const servers=[];
  for(const value of entries) {
    if(typeof value!=="string" || value.length>256 || !value.startsWith("stun:") || value.includes("/") || /\s/.test(value)) throw Error("Use a credential-free UDP STUN URI, such as stun:your-server.example:3478.");
    const raw=value.endsWith("?transport=udp") ? value.slice(0,-14) : value;
    let url;try{url=new URL(raw.replace(/^stun:/,"stun://"));}catch{throw Error("Invalid UDP STUN endpoint.");}
    if(url.username || url.password || url.search || url.hash || url.pathname || !url.hostname || url.port==="0") throw Error("STUN endpoints cannot contain credentials, paths or non-UDP transport settings.");
    const host=url.hostname.toLowerCase();
    if(host==="0.0.0.0" || host==="255.255.255.255" || host==="[::]" || /^\[ff/i.test(host) || /^\[fe[89ab]/i.test(host) || host.startsWith("[::ffff:") || !host.startsWith("[") && !host.replace(/\.$/,"").split(".").every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) || /^2(?:2[4-9]|3\d)\./.test(host)) throw Error("STUN needs a unicast host address or DNS name.");
    const server=`stun:${host}:${url.port || 3478}`;
    if(server.length>256)throw Error("STUN endpoint is too long.");
    if(!servers.includes(server))servers.push(server);
  }
  return servers;
}
