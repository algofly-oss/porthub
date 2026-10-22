const owner = "demo-user";
function sampleAccess(state) {
  const group = (name) => ({
    kind: "group",
    id: state.groups.find((g) => g.name === name)._id,
  });
  const policy = (
    suffix,
    name,
    enabled,
    sources,
    destinations,
    ports,
    bidirectional = false,
  ) => ({
    _id: `demo-policy-${suffix}`,
    user_id: owner,
    name,
    group_id: sources[0].id,
    enabled,
    revision: 1,
    rules: [
      {
        id: `demo-rule-${suffix}`,
        name,
        enabled: true,
        sources,
        destinations,
        protocol: "tcp",
        ports,
        bidirectional,
      },
    ],
  });
  return {
    books: [
      policy(
        "ssh",
        "Developers → Production SSH",
        true,
        [group("Development")],
        [group("Production")],
        "22",
      ),
      policy(
        "web",
        "Development Web Services",
        true,
        [group("Development")],
        [group("Development")],
        "443, 8080",
        true,
      ),
      policy(
        "maintenance",
        "Personal → Production Maintenance",
        false,
        [group("Personal")],
        [group("Production")],
        "22, 8443",
      ),
    ],
    invitations: [
      {
        _id: "demo-invitation-review",
        email: "sam@example.test",
        role: "member",
        expires_at: new Date(Date.now() + 3 * 86400000).toISOString(),
      },
    ],
    network: { cidr: "10.203.0.0/24", dns_suffix: "phub" },
  };
}
export function demoAccess(state, method, path, body, id) {
  state.access ||= sampleAccess(state);
  const access = state.access;
  if (path === "/access/workspaces")
    return { data: [{ id: owner, name: "Demo Workspace", role: "owner" }] };
  const users = [
    {
      _id: owner,
      name: state.user.name,
      email: state.user.email,
      role: "owner",
    },
    {
      _id: "demo-person-alex",
      name: "Alex Morgan",
      email: "alex@example.test",
      role: "admin",
    },
    {
      _id: "demo-person-jamie",
      name: "Jamie Lee",
      email: "jamie@example.test",
      role: "member",
    },
  ].filter(user => !(access.removed_users || []).includes(user._id));
  const machines = state.machines.map((m, index) => ({
    ...m,
    user_id: owner,
    private_owner_id: [owner, "demo-person-alex", "demo-person-jamie"][index % 3],
  }));
  // Private names mirror the API: registered machine name unless customised,
  // and never a name another machine already uses.
  const label = (name) => String(name || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "machine";
  access.hostnames = access.hostnames || {};
  const privatePeers = machines.slice(0, 3).map((m, index) => ({
    _id: `${owner}:${m._id}`, machine_id: m._id, machine_name: m.name, ip: `10.203.0.${11 + index}`,
    hostname: access.hostnames[m._id] || label(m.name), custom_hostname: Boolean(access.hostnames[m._id]),
    enabled: true, installed: true, online: index < 2, paths: index < 2 ? ["direct"] : [],
  }));
  const rename = path.match(/^\/access\/private\/peers\/([^/]+)\/hostname$/);
  if (rename) {
    const peer = privatePeers.find((p) => p._id === decodeURIComponent(rename[1]));
    if (!peer) throw Error("Private peer not found");
    const wanted = String(body.hostname || "").trim().toLowerCase();
    if (!wanted) {
      delete access.hostnames[peer.machine_id];
      return { hostname: label(peer.machine_name) };
    }
    if (!/^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(wanted))
      throw Error("Use up to 48 letters, numbers or hyphens, not starting or ending with a hyphen");
    const clash = machines.find((m) => m._id !== peer.machine_id && label(m.name) === wanted) ||
      privatePeers.find((p) => p.machine_id !== peer.machine_id && p.hostname === wanted);
    if (clash) throw Error(`${wanted} is already used by ${clash.name || clash.machine_name}`);
    access.hostnames[peer.machine_id] = wanted;
    return { hostname: wanted };
  }
  if (path === "/access/snapshot")
    return {
      workspace_id: owner,
      role: "owner",
      transport_ready: false,
      network: access.network,
      machines,
      users,
      groups: state.groups.map((g) => ({ ...g, user_ids: g.user_ids || [] })),
      books: access.books,
      invitations: access.invitations,
      private_peers: privatePeers,
    };
  if (method === "delete" && path.startsWith("/access/members/")) {
    const member = path.split("/").pop();
    if (member === owner) throw Error("The owner cannot be removed");
    access.removed_users = [...(access.removed_users || []), member];
    state.groups.forEach(group => { group.user_ids = (group.user_ids || []).filter(user => user !== member); });
    return { msg: "Removed" };
  }
  if (path === "/access/groups") {
    if (!body.name?.trim()) throw Error("Enter a group name");
    if (state.groups.some((g) => g.name === body.name.trim()))
      throw Error("A group with that name already exists");
    const group = {
      _id: id(state.nextId++),
      name: body.name.trim(),
      user_ids: [],
    };
    state.groups.push(group);
    return { data: group };
  }
  const groupMatch = path.match(/^\/access\/groups\/([^/]+)\/members$/);
  if (groupMatch) {
    const group = state.groups.find((g) => g._id === groupMatch[1]);
    if (!group) throw Error("Group not found");
    group.user_ids = body.user_ids;
    state.machines.forEach((m) => {
      m.group_ids = m.group_ids.filter((g) => g !== group._id);
      if (body.machine_ids.includes(m._id)) m.group_ids.push(group._id);
    });
    return { msg: "Saved" };
  }
  if (path === "/access/books" || path.startsWith("/access/books/")) {
    const existing = access.books.find((b) => b._id === path.split("/").pop());
    if (method === "delete") {
      access.books = access.books.filter((b) => b !== existing);
      return { msg: "Removed" };
    }
    if (!body.name?.trim() || !body.group_id)
      throw Error("Name and organising group are required");
    if (
      body.rules.some(
        (r) => !r.name.trim() || !r.sources.length || !r.destinations.length,
      )
    )
      throw Error("Every rule needs a name, source and destination");
    const book = {
      ...body,
      _id: existing?._id || id(state.nextId++),
      user_id: owner,
      revision: (existing?.revision || 0) + 1,
    };
    // Updates keep their position so a paused policy does not jump.
    access.books = existing
      ? access.books.map((b) => (b === existing ? book : b))
      : [...access.books, book];
    return { data: book };
  }
  if (path === "/access/network") {
    access.network = body;
    return { data: body, transport_ready: false };
  }
  if (path === "/access/invitations") {
    const invitation = {
      _id: id(state.nextId++),
      email: body.email,
      role: body.role,
      expires_at: new Date(Date.now() + 7 * 86400000).toISOString(),
    };
    access.invitations.push(invitation);
    return {
      token: `demo-not-a-real-invitation-${invitation._id}`,
      expires_at: invitation.expires_at,
    };
  }
  if (method === "delete" && path.startsWith("/access/invitations/")) {
    access.invitations = access.invitations.filter(
      (i) => i._id !== path.split("/").pop(),
    );
    return { msg: "Revoked" };
  }
  if (path === "/access/test") {
    const source = machines.find((m) => m._id === body.source_id),
      destination = machines.find((m) => m._id === body.destination_id);
    const match = (selector, machine) =>
      selector.kind === "all"
        ? Boolean(machine)
        : selector.kind === "machine"
        ? selector.id === machine?._id
        : selector.kind === "user"
          ? selector.id === machine?.private_owner_id && users.some(user => user._id === selector.id)
          : machine?.group_ids.includes(selector.id) ||
            (
              state.groups.find((g) => g._id === selector.id)?.user_ids || []
            ).includes(machine?.private_owner_id);
    for (const book of access.books) {
      if (!book.enabled || !state.groups.some((g) => g._id === book.group_id))
        continue;
      for (const rule of book.rules) {
        if (!rule.enabled || !["any", body.protocol].includes(rule.protocol))
          continue;
        const ports = rule.ports.trim();
        if (
          ports &&
          !ports.split(",").some((value) => {
            const [a, b] = value.trim().split("-").map(Number);
            return body.port >= a && body.port <= (b || a);
          })
        )
          continue;
        const direction = (a, b) =>
          rule.sources.some((s) => match(s, a)) &&
          rule.destinations.some((d) => match(d, b));
        if (
          source?.enabled !== false &&
          destination?.enabled !== false &&
          (direction(source, destination) ||
            (rule.bidirectional && direction(destination, source)))
        )
          return {
            data: {
              allowed: true,
              reason: rule.name,
              rule_id: rule.id,
              book_id: book._id,
            },
            transport_ready: false,
          };
      }
    }
    return {
      data: {
        allowed: false,
        reason: "No enabled rule allows this connection",
        rule_id: null,
        book_id: null,
      },
      transport_ready: false,
    };
  }
  throw Error("This access action is unavailable in the demo");
}
