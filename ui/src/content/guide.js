// Product guide content; rendered as safe structured text, never raw HTML.
export const guideArticles = [
  {
    "slug": "overview",
    "group": "Start here",
    "title": "Meet PortHub",
    "description": "Connect machines, publish services and move files from one self-hosted workspace.",
    "sections": [
      {
        "id": "what-it-does",
        "title": "One workspace for your machines",
        "blocks": [
          {
            "type": "paragraph",
            "text": "PortHub combines a self-hosted gateway, a browser dashboard and a native agent. Register a machine once, then manage public ports, private connectivity and file transfers from the same workspace."
          },
          {
            "type": "table",
            "columns": [
              "Component",
              "What it does"
            ],
            "rows": [
              [
                "Gateway",
                "Coordinates registrations and policies, serves the dashboard and API, and relays public mappings and private fallback traffic."
              ],
              [
                "Agent",
                "Runs on each registered machine, maintains service forwarding and private routes, and includes HTTP file serving and transfer tools."
              ],
              [
                "Dashboard",
                "Manages machines, ports, proxies, access rules, traffic and account settings."
              ]
            ]
          }
        ]
      },
      {
        "id": "choose-access",
        "title": "Choose how to connect",
        "blocks": [
          {
            "type": "table",
            "columns": [
              "Need",
              "Use"
            ],
            "rows": [
              [
                "Reach an application from a normal browser or client",
                "A public mapped port or web proxy."
              ],
              [
                "Connect trusted registered machines by private IP or domain",
                "Private networking with an explicit access rule."
              ],
              [
                "Move a file or keep a directory updated",
                "The built-in http.server, http.receive, get and push commands."
              ]
            ]
          }
        ]
      },
      {
        "id": "routes",
        "title": "How traffic moves",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Public mapped ports pass through the gateway. Private connections can use discovered peer connectivity or the gateway fallback. Agents prepare available routes in the background; the selected route depends on availability and the configured strategy."
          },
          {
            "type": "note",
            "text": "A private address is an identity within a PortHub workspace. It is different from the machine’s physical LAN address. Access rules still apply when peers find a direct LAN route."
          }
        ]
      },
      {
        "id": "start",
        "title": "Start with one machine",
        "blocks": [
          {
            "type": "steps",
            "items": [
              "Sign in and open Machines.",
              "Create a machine and copy its generated installation command.",
              "Run the command on that machine, then confirm it appears online.",
              "Choose a public port mapping, private access rule or transfer tutorial from this guide."
            ]
          }
        ]
      }
    ]
  },
  {
    "slug": "getting-started",
    "group": "Start here",
    "title": "Install your first agent",
    "description": "Go from a new workspace to a connected machine.",
    "sections": [
      {
        "id": "enroll",
        "title": "Enroll from the dashboard",
        "blocks": [
          {
            "type": "steps",
            "items": [
              "Open Machines and create a registration with a recognizable name.",
              "Copy the generated install command from the machine’s configuration. Use the command from your own gateway.",
              "Run it on the target machine. Installation may request administrator privileges to create the boot-time service.",
              "Confirm that the machine becomes online in the dashboard. The CLI is registered in the system path."
            ]
          },
          {
            "type": "note",
            "text": "Installer links contain enrollment capabilities. Treat them as credentials and share them only with the person installing that machine. Do not paste real installation links into public documentation."
          }
        ]
      },
      {
        "id": "verify",
        "title": "Verify the installation",
        "blocks": [
          {
            "type": "code",
            "text": "porthub version\nporthub ls\nporthub status",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "The list shows registration IDs, the registered account email, service state, number of ports and gateway. When a command cannot choose between multiple registrations, pass the ID from porthub ls."
          }
        ]
      },
      {
        "id": "platforms",
        "title": "Supported platforms",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Native releases are supplied for Linux, macOS and Windows, including supported x86 and ARM targets. The installer selects the asset for the machine’s OS and CPU. Transfer commands are built into the binary; separate lighttpd, aria2c, curl or rsync installations are not required to use PortHub transfers."
          }
        ]
      },
      {
        "id": "next",
        "title": "Your next step",
        "blocks": [
          {
            "type": "paragraph",
            "text": "For browser access to an application, configure a public mapping or web proxy. For application-to-application private traffic, create an access rule and use the assigned private address or domain. For your first transfer, open the file-transfer tutorial."
          }
        ]
      }
    ]
  },
  {
    "slug": "machines",
    "group": "Networking",
    "title": "Machines and registrations",
    "description": "Understand machine state, configuration and local services.",
    "sections": [
      {
        "id": "configuration",
        "title": "Configure a machine",
        "blocks": [
          {
            "type": "paragraph",
            "text": "The Details tab contains its name, aliases, private DNS domains and identity information. The Ports tab contains service mappings. Logs and history help explain connectivity and uptime. Copy icons next to addresses and domains copy the displayed value."
          }
        ]
      },
      {
        "id": "state",
        "title": "Online, offline and disabled",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Online means the gateway has a recent client connection or heartbeat. Offline means that presence is no longer current. Disabling a machine is an administrative control; it is separate from whether the operating system is powered on."
          },
          {
            "type": "paragraph",
            "text": "The default All machine view omits disabled machines. Online and Offline filter by connection state."
          }
        ]
      },
      {
        "id": "services",
        "title": "Manage registrations from the CLI",
        "blocks": [
          {
            "type": "code",
            "text": "porthub ls\nporthub status\nporthub stop\nporthub start\nporthub restart",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "These commands select the available registration when it is unambiguous. For multiple accounts or registrations, append the registration ID shown by porthub ls. System-service mutations may request elevated privileges; ordinary inspection and transfers do not inherently require administrator access."
          }
        ]
      },
      {
        "id": "remove",
        "title": "Remove a local registration",
        "blocks": [
          {
            "type": "code",
            "text": "porthub remove REGISTRATION_ID",
            "label": "Terminal"
          },
          {
            "type": "note",
            "text": "Removing a registration is different from stopping it. Stop temporarily suspends the service. Remove retires the selected local profile. Review the command’s confirmation and the dashboard before deleting anything you intend to keep."
          }
        ]
      }
    ]
  },
  {
    "slug": "public-ports",
    "group": "Networking",
    "title": "Public port mappings",
    "description": "Expose an application through your gateway without opening a port on the client’s router.",
    "sections": [
      {
        "id": "configure",
        "title": "Create a mapping",
        "blocks": [
          {
            "type": "steps",
            "items": [
              "Start the application on the registered machine or on an address that machine can reach.",
              "Open the machine’s Ports tab and add a mapping.",
              "Set the internal target IP and port. Select the external gateway port and the desired access policy.",
              "Enable the mapping and use the public address displayed in the dashboard."
            ]
          }
        ]
      },
      {
        "id": "addresses",
        "title": "Read the forwarding path",
        "blocks": [
          {
            "type": "paragraph",
            "text": "A path such as 35000 → 192.168.1.20:8080 means that gateway port 35000 forwards to that internal address and port. The internal target may be another reachable host on the registered machine’s network."
          },
          {
            "type": "note",
            "text": "A TCP port mapping does not add HTTP or TLS to your application. Use the protocol your application actually serves. Use a web proxy when you want hostname-based HTTP routing."
          }
        ]
      },
      {
        "id": "gateway",
        "title": "Gateway connectivity and fallback",
        "blocks": [
          {
            "type": "paragraph",
            "text": "The forwarding agent and gateway share the application’s existing ingress rather than requiring a separate Rathole management port. Operator-advertised direct endpoints can avoid an intermediate proxy. If a direct endpoint fails or rejects a connection, the agent can use its configured gateway domain fallback."
          },
          {
            "type": "paragraph",
            "text": "Both HTTP and HTTPS origins are supported. Plain HTTP does not provide transport confidentiality for its authorization headers or raw fallback packets. Choose a trusted transport when that matters for the deployment."
          }
        ]
      },
      {
        "id": "check",
        "title": "Check a failed mapping",
        "blocks": [
          {
            "type": "steps",
            "items": [
              "Confirm that the target application is listening and reachable from the registered machine.",
              "Check that both machine and mapping are enabled.",
              "Check the external port and its firewall/access policy.",
              "Review the machine’s client logs and the traffic view before changing unrelated network rules."
            ]
          }
        ]
      }
    ]
  },
  {
    "slug": "web-proxies",
    "group": "Networking",
    "title": "Web proxies",
    "description": "Give an HTTP service a hostname and inspect its complete target path.",
    "sections": [
      {
        "id": "targets",
        "title": "Choose the target type",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Use a machine/service target for a PortHub-managed mapping, or a standalone URL for an independently reachable HTTP application. Machine targets show their external gateway port and internal IP/port; standalone targets show the configured URL."
          }
        ]
      },
      {
        "id": "setup",
        "title": "Create a proxy",
        "blocks": [
          {
            "type": "steps",
            "items": [
              "Open Proxies and create a route.",
              "Add the hostname that should serve the application. Configure its DNS to reach your gateway.",
              "Choose the registered service or standalone target URL.",
              "Enable the route and open its URL. Use the copy icon to share it accurately."
            ]
          }
        ]
      },
      {
        "id": "tls",
        "title": "DNS and HTTPS",
        "blocks": [
          {
            "type": "paragraph",
            "text": "A hostname entry in PortHub does not by itself publish DNS records or obtain a publicly trusted certificate. Your DNS, gateway TLS configuration or upstream proxy must make the hostname reachable with the intended certificate."
          },
          {
            "type": "note",
            "text": "Avoid pointing a proxy back at the same ingress in a way that creates a loop. Gateway aliases for the dashboard are handled by the gateway’s own routes."
          }
        ]
      }
    ]
  },
  {
    "slug": "private-network",
    "group": "Networking",
    "title": "Private networking",
    "description": "Use assigned private IPs and domains between authorized machines.",
    "sections": [
      {
        "id": "identity",
        "title": "Private identity and domains",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Each private registration belongs to a workspace and receives a private IPv4 address. A domain such as workstation.phub resolves through the private networking setup. These names are intended for participating clients; they are not automatically public internet domains."
          }
        ]
      },
      {
        "id": "connect",
        "title": "Connect two machines",
        "blocks": [
          {
            "type": "steps",
            "items": [
              "Register both machines in the workspace and ensure private registrations are running.",
              "Create an access rule allowing the source to reach the target service and port.",
              "Confirm the target application is listening on a reachable address.",
              "Connect using the target’s private IP or domain from the source machine."
            ]
          }
        ]
      },
      {
        "id": "discovery",
        "title": "LAN discovery and peer identity",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Clients advertise candidate connectivity and can discover a direct local route when both machines share a reachable network. Discovery binds the expected peer identity and certificate; two unrelated machines with the same physical IP must not be treated as the same peer."
          },
          {
            "type": "paragraph",
            "text": "When networks change, agents can prepare another route or use the gateway. Direct connectivity is not guaranteed on every NAT, firewall or ISP. The gateway remains a fallback when it is available."
          }
        ]
      },
      {
        "id": "ranges",
        "title": "Tenant address ranges",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Choose a private RFC1918 IPv4 range in Access Rules → Network. New tenants receive an unused default range. Range changes are checked against other tenant ranges and retained assigned addresses on the same gateway."
          },
          {
            "type": "note",
            "text": "Existing historical ranges and peer addresses are preserved during upgrades. Editing a preference does not silently renumber every existing client. Overlapping operating-system routes can also prevent a private route from being installed."
          }
        ]
      }
    ]
  },
  {
    "slug": "access-rules",
    "group": "Networking",
    "title": "Access rules and workspaces",
    "description": "Keep authorization in place whichever transport is selected.",
    "sections": [
      {
        "id": "rules",
        "title": "Grant only the access you intend",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Rules identify a source, a destination and the allowed service/port. Use machine and group selectors to express shared policies. A discovered direct path does not override the rulebook."
          },
          {
            "type": "steps",
            "items": [
              "Select the correct workspace.",
              "Create or edit a rulebook with explicit source and target selectors.",
              "Set the intended port or service and enable the rule.",
              "Test from an allowed source, then confirm an unrelated source is still denied."
            ]
          }
        ]
      },
      {
        "id": "members",
        "title": "Workspace membership",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Workspace roles determine who can manage machines and policies. Inviting a user to a workspace does not transfer ownership of their unrelated machines. A machine can have registrations associated with different accounts; use the account email and registration ID in the CLI to tell them apart."
          }
        ]
      },
      {
        "id": "receiver",
        "title": "A receiver is still required",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Permission to reach a machine is not permission to write arbitrary files on it. File uploads require a deliberately started http.receive server, or http.server with --upload. Public exposure of a receiver follows the public mapping policy; private exposure follows private access rules."
          }
        ]
      }
    ]
  },
  {
    "slug": "private-dns",
    "group": "Networking",
    "title": "Private DNS domains",
    "description": "Name your machines without changing their identity.",
    "sections": [
      {
        "id": "default",
        "title": "The default domain",
        "blocks": [
          {
            "type": "paragraph",
            "text": "A machine’s primary name is combined with the workspace’s DNS suffix, such as desktop.phub. The suffix is shown beside the machine name in Details. Changing the global suffix updates the default domain names generated from it."
          }
        ]
      },
      {
        "id": "aliases",
        "title": "Additional private domains",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Expand the additional private domains section in Details to add custom name/suffix combinations. Domain names must not conflict with another registered machine or alias. Reorder the list to choose which domain the table’s copy action uses."
          }
        ]
      },
      {
        "id": "browser",
        "title": "Open private names in a browser",
        "blocks": [
          {
            "type": "code",
            "text": "http://desktop.phub:8000/",
            "label": "Browser address"
          },
          {
            "type": "paragraph",
            "text": "Include http:// or https:// when your browser treats an unfamiliar private suffix as a search query. An arbitrary suffix is not a public DNS registration; the connecting machine still needs PortHub’s private DNS and access."
          }
        ]
      }
    ]
  },
  {
    "slug": "path-strategies",
    "group": "Networking",
    "title": "Path strategies",
    "description": "Let agents choose automatically, or express a preference.",
    "sections": [
      {
        "id": "auto",
        "title": "Start with Auto",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Auto selects from prepared available transports. Direct peer connectivity can reduce gateway load; gateway forwarding remains useful when it is more reliable or performs better. Route preparation happens in the background rather than requiring a bandwidth test for every application connection."
          }
        ]
      },
      {
        "id": "override",
        "title": "Inspect and override",
        "blocks": [
          {
            "type": "code",
            "text": "porthub path show\nporthub path set prefer-direct\nporthub path set prefer-gateway\nporthub path reset",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "The available modes are auto, prefer-direct and prefer-gateway. A preference is not a guarantee that a currently unavailable path can be used. Add the registration selector when more than one private registration exists."
          }
        ]
      },
      {
        "id": "stability",
        "title": "Keep transfers stable",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Path preferences primarily affect route selection for new flows. Supported stream transports retain their connection across carrier changes, but not every failure can be hidden: an application restart, machine reboot or agent upgrade can still interrupt traffic."
          },
          {
            "type": "note",
            "text": "Do not repeatedly switch strategies while diagnosing a transfer. Compare stable runs using the same endpoints, direction, file size and connection count."
          }
        ]
      }
    ]
  },
  {
    "slug": "file-transfer",
    "group": "Transfers",
    "title": "Your first file transfer",
    "description": "Move data between two machines with tools already inside the agent.",
    "sections": [
      {
        "id": "download",
        "title": "Pull a file",
        "blocks": [
          {
            "type": "steps",
            "items": [
              "On the source machine, start a server in the directory you want to share.",
              "Allow access to port 8000 through private rules or a public mapping.",
              "Run get on the receiving machine with the appropriate reachable URL."
            ]
          },
          {
            "type": "code",
            "text": "porthub http.server ./public\n\n# On the receiving machine\nporthub get \"http://source.phub:8000/archive.zip\" --dir ./downloads",
            "label": "Terminal"
          }
        ]
      },
      {
        "id": "upload",
        "title": "Push a file or directory",
        "blocks": [
          {
            "type": "steps",
            "items": [
              "On the destination, explicitly start a receiver.",
              "Allow the sender to reach the receiver’s port.",
              "Push a file or directory to its URL. Nested URL paths are created under the receiver root."
            ]
          },
          {
            "type": "code",
            "text": "porthub http.receive ./incoming\n\n# On the sending machine\nporthub push ./dataset \"http://destination.phub:8001/projects/run-01/\"",
            "label": "Terminal"
          }
        ]
      },
      {
        "id": "public",
        "title": "Use public access instead",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Replace the private hostname and local service port with the public gateway address and mapped external port. The transfer protocol is the same; only the reachable address changes. A public mapping relays through the gateway."
          }
        ]
      },
      {
        "id": "scope",
        "title": "Know what is shared",
        "blocks": [
          {
            "type": "note",
            "text": "The HTTP server serves its selected directory. The receiver accepts uploads under its selected root. Bind to 127.0.0.1 for local-only use, or restrict reachability with PortHub access rules and your network policy."
          }
        ]
      }
    ]
  },
  {
    "slug": "get",
    "group": "Transfers",
    "title": "Download with get",
    "description": "Parallel downloads, safe resume and ordinary HTTP servers.",
    "sections": [
      {
        "id": "urls",
        "title": "Use standard URLs",
        "blocks": [
          {
            "type": "code",
            "text": "porthub get \"https://example.com/archive.zip\"\nporthub get \"https://example.com/archive.zip?token=VALUE\" --dir ./downloads\nporthub get \"https://example.com/archive.zip\" -x 1",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "get works with ordinary HTTP and HTTPS download endpoints. It defaults to 16 connections when byte ranges permit parallelism and falls back to a single connection when ranges are unavailable. It does not turn a webpage or login screen into a direct file download."
          }
        ]
      },
      {
        "id": "resume",
        "title": "Resume safely",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Retry the same command to reuse compatible partial download state. PortHub checks the remote object’s identity before continuing. If a server cannot support a safe range resume, the download restarts rather than appending incompatible data."
          },
          {
            "type": "code",
            "text": "porthub get \"https://example.com/archive.zip\" --sha256 EXPECTED_SHA256",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "Use --sha256 when you have a trusted expected digest. A filename or successful HTTP response alone is not an integrity check."
          }
        ]
      },
      {
        "id": "filename",
        "title": "How the filename is chosen",
        "blocks": [
          {
            "type": "paragraph",
            "text": "The server’s Content-Disposition filename takes precedence. Otherwise, PortHub uses the last non-empty URL path component after removing trailing slashes. Query parameters do not become part of the filename. Unsafe filesystem characters are sanitized."
          },
          {
            "type": "table",
            "columns": [
              "URL without a server filename",
              "Saved name"
            ],
            "rows": [
              [
                "https://example.com/file.zip/?token=abc",
                "file.zip"
              ],
              [
                "https://example.com/download?id=123",
                "download"
              ],
              [
                "https://example.com/",
                "download.bin"
              ]
            ]
          },
          {
            "type": "paragraph",
            "text": "PortHub cannot infer an original filename or extension that neither the server nor the path provides. Quote URLs containing ? or & in your shell."
          }
        ]
      },
      {
        "id": "directories",
        "title": "Pull directories from a PortHub server",
        "blocks": [
          {
            "type": "code",
            "text": "porthub get \"http://source.phub:8000/dataset/\" --dir ./downloads\nporthub get \"http://source.phub:8000/dataset/\" --dir ./dataset --contents-only",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "A PortHub HTTP server supplies the directory metadata needed for directory downloads. Ordinary servers may offer only an HTML listing, which does not provide the same sync protocol."
          }
        ]
      }
    ]
  },
  {
    "slug": "push",
    "group": "Transfers",
    "title": "Upload with push",
    "description": "Send files or synchronize directories without a separate rsync client.",
    "sections": [
      {
        "id": "basic",
        "title": "Files and directories",
        "blocks": [
          {
            "type": "code",
            "text": "porthub push ./file.bin \"http://destination.phub:8001/\"\nporthub push ./dataset \"http://destination.phub:8001/backups/project/\"\nporthub push ./dataset \"http://destination.phub:8001/backups/project/\" --contents-only",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "Directories retain their top-level folder by default. --contents-only places their contents directly under the destination URL path. Missing destination subdirectories are created under the receiver’s root."
          }
        ]
      },
      {
        "id": "incremental",
        "title": "Incremental transfer and resume",
        "blocks": [
          {
            "type": "paragraph",
            "text": "PortHub’s sender and receiver exchange metadata and upload state to avoid resending completed work. The default skip decision uses file size and modification time. A changed file is reconsidered on the next sync."
          },
          {
            "type": "code",
            "text": "porthub push ./dataset \"http://destination.phub:8001/\" --force",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "Use --force when you need to resend files even if size and modification time match. The sync behavior is rsync-like; it does not require or implement the standard rsync wire protocol."
          }
        ]
      },
      {
        "id": "parallel",
        "title": "Choose concurrency",
        "blocks": [
          {
            "type": "code",
            "text": "porthub push ./dataset \"http://destination.phub:8001/\" -x 16\nporthub push ./dataset \"http://destination.phub:8001/\" -x 1",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "The default is 16 connections. Reduce it on a constrained receiver or to compare a single connection. Slow disks create backpressure; more connections cannot make a disk write faster."
          }
        ]
      },
      {
        "id": "permissions",
        "title": "Receiver and permissions",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Start the receiver manually before sending. push cannot remotely create a receiver on an arbitrary machine. Ordinary filesystem permissions still apply; use elevated privileges only when reading or writing the selected files requires them."
          }
        ]
      }
    ]
  },
  {
    "slug": "watch-sync",
    "group": "Transfers",
    "title": "Keep a directory in sync",
    "description": "Watch for changes in the foreground or as a managed background job.",
    "sections": [
      {
        "id": "start",
        "title": "Watch a directory",
        "blocks": [
          {
            "type": "code",
            "text": "porthub push ./data \"http://destination.phub:8001/projects/data/\" -w\nporthub push ./data \"http://destination.phub:8001/projects/data/\" -w -d",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "-w is --watch. -d is --detach, following Docker’s spelling. Without --detach, watch runs in the current terminal. The receiver must remain running and reachable."
          }
        ]
      },
      {
        "id": "changes",
        "title": "What changes are transferred",
        "blocks": [
          {
            "type": "paragraph",
            "text": "New and modified files are considered for transfer. A file with the same name and changed contents is uploaded again when its size or modification time changes. Use --force if you deliberately preserve both metadata fields while changing contents."
          },
          {
            "type": "note",
            "text": "This is an update-oriented directory sync, not a destructive mirror. Deleting a local file does not automatically delete the remote copy. Symlinks and unsafe paths are restricted; do not rely on it to clone filesystem metadata, devices or ownership."
          }
        ]
      },
      {
        "id": "manage",
        "title": "Manage background jobs",
        "blocks": [
          {
            "type": "code",
            "text": "porthub sync list\nporthub sync status JOB_ID\nporthub sync stop JOB_ID",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "Jobs are scoped to the user who started them. A job launched with elevated privileges belongs to that elevated user. Stopping a job keeps already transferred files."
          }
        ]
      }
    ]
  },
  {
    "slug": "http-servers",
    "group": "Transfers",
    "title": "HTTP server and receiver",
    "description": "Serve downloads or accept uploads, and manage every running instance.",
    "sections": [
      {
        "id": "commands",
        "title": "Choose the server mode",
        "blocks": [
          {
            "type": "table",
            "columns": [
              "Command",
              "Default port",
              "Capabilities"
            ],
            "rows": [
              [
                "porthub http.server ./public",
                "8000",
                "Downloads, directory listings and range requests."
              ],
              [
                "porthub http.receive ./incoming",
                "8001",
                "Uploads from PortHub push and standard HTTP clients."
              ],
              [
                "porthub http.server ./public --upload",
                "8000",
                "Downloads plus the upload receiver."
              ]
            ]
          },
          {
            "type": "paragraph",
            "text": "Enabling --upload adds receiver capabilities to http.server. Choose a directory appropriate for both reading and writing before enabling it."
          }
        ]
      },
      {
        "id": "multiple",
        "title": "Run multiple servers",
        "blocks": [
          {
            "type": "code",
            "text": "porthub http.server ./public -p 8000\nporthub http.server ./reports -p 8002\nporthub http.receive ./incoming -p 8001\nporthub http.receive ./other -p 8003",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "Each instance needs a free port. The registered HTTP processes can be listed and stopped even after the original terminal is lost."
          }
        ]
      },
      {
        "id": "stop",
        "title": "List and stop servers",
        "blocks": [
          {
            "type": "code",
            "text": "porthub http.server list\nporthub http.server stop 8000\nporthub http.receive list\nporthub http.receive stop 8001",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "Use --all with stop only when you intend to stop every matching managed instance for that user. These commands do not terminate unrelated web servers."
          }
        ]
      },
      {
        "id": "standard",
        "title": "Use a standard client",
        "blocks": [
          {
            "type": "code",
            "text": "curl -o archive.zip \"http://source.phub:8000/archive.zip\"\ncurl --upload-file ./file.bin \"http://destination.phub:8001/file.bin\"\ncurl -X POST --data-binary @./file.bin \"http://destination.phub:8001/file.bin\"",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "Standard clients can transfer normal files using their supported HTTP methods. PortHub-to-PortHub tools add directory metadata, resumable parallel transfer and watch-job management; curl does not automatically inherit those extra protocols."
          }
        ]
      }
    ]
  },
  {
    "slug": "traffic-and-logs",
    "group": "Operations",
    "title": "Traffic, logs and diagnostics",
    "description": "Understand a path before changing it.",
    "sections": [
      {
        "id": "traffic",
        "title": "Read the traffic views",
        "blocks": [
          {
            "type": "paragraph",
            "text": "The dashboard highlights busy services. Traffic Explorer provides per-machine and per-port activity, including the external gateway port and internal target. Select a time window and sort to compare the services you care about."
          }
        ]
      },
      {
        "id": "logs",
        "title": "Read machine logs",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Open a machine’s Logs tab to request its agent diagnostics. The agent must be online and authorized. Logs are streamed on demand rather than collected by a remote shell. A disconnected agent cannot supply a live log stream."
          }
        ]
      },
      {
        "id": "benchmark",
        "title": "Compare throughput fairly",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Compare public and private paths using the same file, direction, connection count and disk target. Report MB/s separately from Mbit/s: 50 MB/s is approximately 400 Mbit/s. A parallel transfer and a single connection are different measurements."
          },
          {
            "type": "paragraph",
            "text": "An ISP rate is a ceiling rather than a guaranteed application rate. Disk speed, other traffic, gateway location, packet loss and CPU can affect sustained throughput."
          }
        ]
      },
      {
        "id": "debug",
        "title": "A short diagnostic checklist",
        "blocks": [
          {
            "type": "steps",
            "items": [
              "Check porthub ls and porthub status on each endpoint.",
              "Confirm the target server is running and listening on the expected address.",
              "Verify the selected workspace, access rule and public mapping.",
              "Check DNS resolution and compare the private IP with the private name.",
              "Inspect logs and path strategy. Change one setting at a time."
            ]
          }
        ]
      }
    ]
  },
  {
    "slug": "updates",
    "group": "Operations",
    "title": "Agent updates",
    "description": "Keep platform releases consistent and inspect the installed version.",
    "sections": [
      {
        "id": "version",
        "title": "Check the version",
        "blocks": [
          {
            "type": "code",
            "text": "porthub version\nporthub version --verbose\nporthub update --check",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "The normal version is major.minor.patch. Verbose output includes source and platform information. The gateway’s client catalog advertises the packaged binary for each supported OS and CPU."
          }
        ]
      },
      {
        "id": "automatic",
        "title": "Automatic and manual updates",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Connected native agents receive update instructions from the gateway. They verify the release metadata and downloaded binary before queuing an update. You do not need to SSH into each machine for routine gateway-driven updates."
          },
          {
            "type": "code",
            "text": "porthub update",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "When multiple registrations exist, use the relevant registration ID. A stopped machine cannot complete an update until it reconnects. Do not treat an accepted maintenance job as proof that installation has finished; check the reported installed version."
          }
        ]
      },
      {
        "id": "interruption",
        "title": "Plan around service restarts",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Agent updates can restart the registered service. Schedule upgrades with active transfers in mind. Path-change resilience does not make a process restart invisible to every application."
          }
        ]
      }
    ]
  },
  {
    "slug": "platform-admin",
    "group": "Operations",
    "title": "Platform administration",
    "description": "Control account access and documentation from the platform workspace.",
    "sections": [
      {
        "id": "settings",
        "title": "Platform settings",
        "blocks": [
          {
            "type": "paragraph",
            "text": "The Platform tab is available to administrators. Its settings control public signups and API documentation. Environment values provide startup defaults; an explicit value saved in the app takes precedence. Reset returns to the environment default."
          }
        ]
      },
      {
        "id": "accounts",
        "title": "Manage accounts",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Administrators can create member accounts using a name, email address and password even when public signup is disabled. Share credentials through a trusted channel; passwords are stored as hashes and cannot be retrieved later."
          },
          {
            "type": "paragraph",
            "text": "Deleting an account requires explicit confirmation. Review the affected machines, mappings and workspace resources before proceeding. Account deletion removes access and related backend resources; it is not a request to delete arbitrary files stored on the person’s computer."
          }
        ]
      },
      {
        "id": "api",
        "title": "API documentation",
        "blocks": [
          {
            "type": "paragraph",
            "text": "When enabled, /api redirects to the API documentation. Disabling API documentation hides both the UI and its OpenAPI JSON. That setting does not disable the API endpoints required by the app and agents."
          },
          {
            "type": "note",
            "text": "This user guide documents product workflows and remains separate from the configurable API endpoint reference."
          }
        ]
      },
      {
        "id": "deployment",
        "title": "Production isolation",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Production uses core, edge and firewall containers. Core contains the API, static UI and database in an isolated network namespace. Edge owns public ingress, and firewall receives the network capability needed for policy enforcement. Persistent state uses configured host bind mounts."
          }
        ]
      }
    ]
  },
  {
    "slug": "troubleshooting",
    "group": "Operations",
    "title": "Troubleshooting and common questions",
    "description": "Recover connectivity without throwing away useful state.",
    "sections": [
      {
        "id": "session",
        "title": "“Could not reconnect” on sign-in",
        "blocks": [
          {
            "type": "paragraph",
            "text": "This message means the account request did not complete with a recognizable signed-in or signed-out response. Try again after checking gateway reachability. Temporary failures preserve the saved session. An explicit signed-out response returns you to the sign-in page."
          },
          {
            "type": "paragraph",
            "text": "A browser shortcut and a normal browser tab can have different storage contexts. Also check that you are opening the intended gateway hostname and scheme; cookies are scoped by browser origin and security attributes."
          }
        ]
      },
      {
        "id": "dns",
        "title": "A private name becomes a search",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Enter a full URL such as http://desktop.phub:8000/. Confirm that the machine running your browser has the private agent and the relevant access rule. Public DNS alone does not resolve a private PortHub name."
          }
        ]
      },
      {
        "id": "port",
        "title": "A server port is occupied",
        "blocks": [
          {
            "type": "code",
            "text": "porthub http.server list\nporthub http.receive list\nporthub sync list",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "Stop the matching managed instance instead of terminating unrelated processes. If no PortHub instance owns the port, another application may be using it."
          }
        ]
      },
      {
        "id": "speed",
        "title": "A transfer is slower than expected",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Start with the same file and one connection on both paths, then compare the default parallel transfer. Verify disk write speed, network direction, strategy and concurrent workloads. Increasing connection count cannot exceed the slowest resource in the path."
          }
        ]
      },
      {
        "id": "help",
        "title": "Find exact command options",
        "blocks": [
          {
            "type": "code",
            "text": "porthub --help\nporthub get --help\nporthub push --help\nporthub http.server --help\nporthub path --help",
            "label": "Terminal"
          },
          {
            "type": "paragraph",
            "text": "The installed binary’s help is the reference for its exact supported flags. Examples in this guide use the current native CLI; older installed clients may need an update."
          }
        ]
      }
    ]
  },
  {
    "slug": "temporary-exposure",
    "group": "Networking",
    "title": "Temporary CLI tunnels",
    "description": "Expose a local service using an existing registered account.",
    "sections": [
      {
        "id": "start",
        "title": "Expose a local port",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Start your local application first. PortHub authenticates with the selected machine registration and reserves a free port from the gateway\u2019s normal public port range. The terminal prints the public address."
          },
          {
            "type": "code",
            "label": "Terminal",
            "text": "porthub expose 3000"
          },
          {
            "type": "paragraph",
            "text": "Leave the terminal open. Press Ctrl+C to release the mapping. If the agent loses connectivity, the gateway expires its temporary lease. Stopping the local application alone does not stop the exposure."
          }
        ]
      },
      {
        "id": "options",
        "title": "Choose a port, subdomain or background mode",
        "blocks": [
          {
            "type": "code",
            "label": "Terminal",
            "text": "porthub expose 3000 --port 35000"
          },
          {
            "type": "paragraph",
            "text": "The requested gateway port must be in the allowed range and unused. CLI tunnels and dashboard mappings share the same reservations."
          },
          {
            "type": "code",
            "label": "Terminal",
            "text": "porthub expose 3000 --subdomain myapp -d"
          },
          {
            "type": "paragraph",
            "text": "The optional subdomain creates a web proxy under the gateway\u2019s configured domain. Without this flag, only the public port is created. Use --registration ID when the machine has multiple registrations."
          }
        ]
      },
      {
        "id": "manage",
        "title": "List and stop temporary tunnels",
        "blocks": [
          {
            "type": "code",
            "label": "Terminal",
            "text": "porthub expose list"
          },
          {
            "type": "code",
            "label": "Terminal",
            "text": "porthub expose stop ID"
          },
          {
            "type": "paragraph",
            "text": "Temporary ports and proxies appear in the account dashboard with an agent-managed indicator. Manage their lifetime through the CLI; dashboard editing is disabled."
          }
        ]
      }
    ]
  },
  {
    "slug": "exit-nodes",
    "group": "Networking",
    "title": "Exit nodes",
    "description": "Route internet connections through one or more registered machines.",
    "sections": [
      {
        "id": "create",
        "title": "Configure routing peers and consumers",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Open Access rules \u2192 Routes and create an exit node. Select machines or groups as routing peers, then select the machines or groups that will use them. Routing peers provide internet egress; consuming machines send their internet traffic through the selected peers. A machine cannot be both roles in a routing loop."
          }
        ]
      },
      {
        "id": "selection",
        "title": "Choose the connection strategy",
        "blocks": [
          {
            "type": "table",
            "columns": [
              "Strategy",
              "Behavior"
            ],
            "rows": [
              [
                "Sticky (default)",
                "A stable client hash selects one available exit for that client\u2019s new connections."
              ],
              [
                "Round robin",
                "Successive new connections alternate between available exits."
              ],
              [
                "Random",
                "Each new connection independently selects an available exit."
              ]
            ]
          },
          {
            "type": "paragraph",
            "text": "Established connections retain their selected exit when you change the strategy. Round robin balances connection counts, not bytes. A single long transfer uses one exit. If that exit goes offline, the connection can fail; another public source address cannot transparently take over its TCP session."
          }
        ]
      },
      {
        "id": "compatibility",
        "title": "Supported traffic",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Exit routing currently requires compatible Linux agents and transports IPv4. New IPv6 internet traffic is rejected while the exit is active so applications can fall back to IPv4. Established IPv6 traffic and directly attached LAN access remain available. This is not an IPv6 full tunnel. One machine can have only one active system-wide exit policy."
          }
        ]
      }
    ]
  },
  {
    "slug": "public-access-lock",
    "group": "Networking",
    "title": "Lock public web access",
    "description": "Require a PIN or API key before forwarding HTTP requests.",
    "sections": [
      {
        "id": "configure",
        "title": "Enable a public access lock",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Open a machine\u2019s port configuration and its Access settings. Choose Off, a six-digit PIN, or an API key. Locks are off by default. Save a new secret to replace the previous one; existing browser sessions are invalidated when the gate is replaced. The same mapping\u2019s direct gateway port and web proxy enforce the lock."
          }
        ]
      },
      {
        "id": "browser",
        "title": "Use a browser or API client",
        "blocks": [
          {
            "type": "paragraph",
            "text": "A browser without an authenticated session sees a sign-in form. Enter the configured PIN or key to continue. Programmatic clients can send the credential in the X-PortHub-Key header."
          },
          {
            "type": "code",
            "label": "Terminal",
            "text": "curl -H 'X-PortHub-Key: YOUR_KEY' http://GATEWAY:PORT/"
          },
          {
            "type": "paragraph",
            "text": "The gateway removes the authentication header before forwarding to the application. Use HTTPS when available to protect credentials in transit; an HTTP URL does not encrypt them."
          }
        ]
      },
      {
        "id": "protocols",
        "title": "HTTP service requirement",
        "blocks": [
          {
            "type": "paragraph",
            "text": "The lock operates on HTTP requests. It is not a login layer for SSH, database protocols or raw TLS passthrough. HTTPS web proxies can terminate TLS before forwarding to the protected HTTP service."
          }
        ]
      }
    ]
  },
  {
    "slug": "dns-controls",
    "group": "Networking",
    "title": "DNS controls",
    "description": "Block or override domains for selected registered machines.",
    "sections": [
      {
        "id": "rules",
        "title": "Configure a domain rule",
        "blocks": [
          {
            "type": "paragraph",
            "text": "Open the DNS controls in Access rules. Select the machines that should receive the rule, then choose Block or Override. A block returns a DNS failure for the configured domain. An override returns the configured IP address. Private PortHub identity zones cannot be replaced by these rules."
          }
        ]
      },
      {
        "id": "limits",
        "title": "Understand the boundary",
        "blocks": [
          {
            "type": "paragraph",
            "text": "These rules apply to the managed operating-system DNS path. They do not guarantee blocking for applications using their own encrypted DNS, a VPN, cached addresses or direct IP connections. An IP override does not rewrite a URL or provide a certificate for another website. HTTPS still checks the original hostname, so mapping one unrelated HTTPS site to another will usually produce a certificate error."
          }
        ]
      }
    ]
  }
];
export const guideGroups = ["Start here", "Networking", "Transfers", "Operations"];
