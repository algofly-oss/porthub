import subprocess

from .env import NFT_TABLE, RECENT_IP_TTL


def build_rules(state: dict[str, dict]) -> str:
    set_lines = []
    counter_lines = []
    input_lines = ["        type filter hook input priority 0;"]
    output_lines = ["        type filter hook output priority 0;"]

    for port in sorted(state.keys(), key=lambda value: int(value)):
        config = state[port]
        allowed_ips = list(config.get("allowed_ips") or [])

        counter_lines.extend(
            [
                f"    counter cnt_in_{port} {{}}",
                f"    counter cnt_out_{port} {{}}",
                f"    counter cnt_drop_{port} {{}}",
                "",
            ]
        )

        set_lines.extend(
            [
                f"    set recent_{port} {{",
                "        type ipv4_addr;",
                "        flags dynamic, timeout;",
                f"        timeout {RECENT_IP_TTL}s;",
                "    }",
                "",
            ]
        )

        if allowed_ips:
            ip_elements = ", ".join(allowed_ips)
            set_lines.extend(
                [
                    f"    set allow_{port} {{",
                    "        type ipv4_addr;",
                    f"        elements = {{ {ip_elements} }}",
                    "    }",
                    "",
                ]
            )
            input_lines.append(
                f'        tcp dport {port} ct state new update @recent_{port} {{ ip saddr timeout {RECENT_IP_TTL}s }}'
            )
            input_lines.append(
                f'        tcp dport {port} ip saddr @allow_{port} counter name "cnt_in_{port}" accept'
            )
            input_lines.append(
                f'        tcp dport {port} ct state new counter name "cnt_drop_{port}" drop'
            )
        else:
            input_lines.append(
                f'        tcp dport {port} ct state new update @recent_{port} {{ ip saddr timeout {RECENT_IP_TTL}s }}'
            )
            input_lines.append(
                f'        tcp dport {port} counter name "cnt_in_{port}" accept'
            )

        output_lines.append(f'        tcp sport {port} counter name "cnt_out_{port}" accept')

    lines = [f"table {NFT_TABLE} {{"]
    lines.extend(counter_lines)
    lines.extend(set_lines)
    lines.extend(
        [
            "    chain input {",
            *input_lines,
            "    }",
            "",
            "    chain output {",
            *output_lines,
            "    }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def apply_rules(state: dict[str, dict]) -> None:
    subprocess.run(
        ["nft", "delete", "table", *NFT_TABLE.split()],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    rules = build_rules(state)
    subprocess.run(["nft", "-f", "-"], input=rules.encode("utf-8"), check=True)
