# Host ports

PortHub uses Docker host networking. It binds directly on the host, with no
Docker `ports:` mappings. A host-facing listener may still be restricted by
host firewall rules, cloud firewall rules, or a connection's IP allowlist.

| Bind | Ports | Purpose |
| --- | --- | --- |
| All interfaces | `80`, `443` | Published web proxies and domain-based access to the app/API |
| All interfaces | `8345`, `8346` | Direct app/API HTTP and HTTPS access, including configured fallback URLs |
| All interfaces | Each enabled forwarding rule's external port | Public access to the configured machine service |
| Loopback | `47080` | Go API and forwarding gateway backend |
| Loopback | `47030` | Next.js UI backend |
| Loopback | `47017` | MongoDB |
| Loopback | `47001` | Firewall policy service |
| Loopback | `47091` | Private-network WebSocket relay backend |

Agents use the existing API HTTP(S) listeners. The gateway does not need its
own public port. The optional `PORTHUB_TUNNEL_LEGACY_LISTEN` setting is only for
a temporary migration from older TCP clients; leave it unset normally.

Internal loopback ports keep the supervised components separate inside the
single container. They are reachable locally on the host and are not direct
network entry points. The API handles public forwarding in-process. Its payload
streams do not go through the database or firewall HTTP service.

Forwarding ports are user configuration, rather than a fixed deployment range.
Inspect them in the dashboard or with:

```sh
docker exec porthub porthub-api clients --connections
```
