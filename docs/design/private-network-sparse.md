
### Local authenticated flow authority checkpoint (not runtime readiness)

The experimental flow context captures one locked sparse pair view: metadata,
compiled directional ACL, and both original base/pair request witnesses. Each
endpoint has its own local policy epoch; reciprocal epochs need not be equal.
The common digest binds workspace, both exact peer descriptors, both local epoch
labels, nonce, and TCP ports. A received remote label never grants local access:
each endpoint separately checks its own captured epoch, service-direction mask,
identity, and original bounded witness. Renewing a cache entry does not reset an
already captured request start.

Tagged native reads additionally carry their original stack scope, connection
generation, and tuple. Another connection cannot adopt a read even when its TCP
tuple matches. The raw byte sender method is private to the experimental chunk
module. These are admission building blocks only: authenticated flow-open wire
exchange, the native-read-only source facade, DATA/FIN duplex runtime hookup,
multiplexing/fairness, and native three-OS retirement proof remain open. No
production capability or default is enabled by this checkpoint.
