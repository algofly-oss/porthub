# Host ports

PortHub uses Docker host networking. It binds directly on the host, with no
Docker `ports:` mappings. A host-facing listener may still be restricted by
host firewall rules, cloud firewall rules, or a connection's IP allowlist.

| Bind | Ports | Purpose |
| --- | --- | --- |
| All interfaces | `80`, `443` | Published web proxies and domain-based access to the app/API |
| All interfaces | `8345`, `8346` | Direct app/API HTTP and HTTPS access, including configured fallback URLs |
| All interfaces | Each enabled forwarding rule's external port | Public access to the configured machine service |
| Core container loopback | `47017` | MongoDB |
| Core container loopback | `47030` | Development-only Next.js UI |
| Core container loopback | `47080` | Development-only API listener |
| Core container loopback | `47001` | Firewall policy compatibility listener, when enabled |
| Core container loopback | `47091` | Private-network relay backend, when enabled |

Agents use the existing API HTTP(S) listeners. The gateway does not need its
own public port. The optional `PORTHUB_TUNNEL_LEGACY_LISTEN` setting is only for
a temporary migration from older TCP clients; leave it unset normally.

Internal loopback ports belong to the isolated core container. They are not
host listeners. The production API and edge communicate over scoped Unix
sockets; development-only loopback backends are also isolated from the host.
The API handles public forwarding in-process. Payload streams do not go through
the database or firewall HTTP service.

Forwarding ports are user configuration, rather than a fixed deployment range.
Inspect them in the dashboard or with:

```sh
docker exec porthub-core porthub-api clients --connections
```
