let temporaryIdentity;
export function imageRoomVisitor() {
  const key = "porthub:image-room-visitor:v1";
  let durable = true;
  try {
    const saved = localStorage.getItem(key);
    if (/^[a-f0-9]{64}$/.test(saved || "")) return { id: saved, durable };
  } catch { durable = false; }
  const id = temporaryIdentity || Array.from(crypto.getRandomValues(new Uint8Array(32)), value => value.toString(16).padStart(2, "0")).join("");
  temporaryIdentity = id;
  try { localStorage.setItem(key, id); } catch { durable = false; }
  return { id, durable };
}
