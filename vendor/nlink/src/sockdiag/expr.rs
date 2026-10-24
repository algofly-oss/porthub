//! Socket filter expressions with ss-compatible syntax.
//!
//! Supports boolean expressions for filtering sockets:
//!
//! ```no_run
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::sockdiag::expr::FilterExpr;
//!
//! let expr = FilterExpr::parse("sport = :22 or dport = :22")?;
//! let expr = FilterExpr::parse("dst 192.168.0.0/16 and state established")?;
//! let expr = FilterExpr::parse("( sport = :80 or sport = :443 ) and state listening")?;
//! # Ok(())
//! # }
//! ```

use std::net::IpAddr;

use winnow::{
    ascii::{digit1, multispace0, multispace1},
    combinator::opt,
    error::{ContextError, ErrMode},
    prelude::*,
    token::take_while,
};

use super::{
    socket::{InetSocket, SocketInfo},
    types::{SocketState, TcpState},
};

/// Socket filter expression AST.
#[derive(Debug, Clone)]
pub enum FilterExpr {
    /// Match source port.
    Sport(Comparison, u16),
    /// Match destination port.
    Dport(Comparison, u16),
    /// Match source address/prefix.
    Src(IpAddr, u8),
    /// Match destination address/prefix.
    Dst(IpAddr, u8),
    /// Match socket state.
    State(SocketState),
    /// Logical AND.
    And(Box<FilterExpr>, Box<FilterExpr>),
    /// Logical OR.
    Or(Box<FilterExpr>, Box<FilterExpr>),
    /// Logical NOT.
    Not(Box<FilterExpr>),
}

/// Comparison operator for port filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Comparison {
    fn apply(self, lhs: u16, rhs: u16) -> bool {
        match self {
            Self::Eq => lhs == rhs,
            Self::Ne => lhs != rhs,
            Self::Lt => lhs < rhs,
            Self::Le => lhs <= rhs,
            Self::Gt => lhs > rhs,
            Self::Ge => lhs >= rhs,
        }
    }
}

impl FilterExpr {
    /// Parse a filter expression string (ss-compatible syntax).
    ///
    /// Supported syntax:
    /// - `sport = :22` or `sport eq :22` — source port comparison
    /// - `dport != :80` or `dport ne :80` — destination port comparison
    /// - `sport > :1024` — port range comparison
    /// - `src 192.168.0.0/16` — source address/prefix match
    /// - `dst 10.0.0.1` — destination address match
    /// - `state established` — state match
    /// - `expr and expr` — logical AND
    /// - `expr or expr` — logical OR
    /// - `not expr` — logical NOT
    /// - `( expr )` — grouping
    ///
    /// The **whole** input must be consumed. A trailing token the grammar does
    /// not recognize is an error, not a stopping point: before #224 the parser
    /// returned `Ok` with the remainder unread, so `sport = :22 && dport = :80`
    /// silently parsed as just `sport = :22` — a *superset* of the sockets
    /// asked for, and one marked exact, so not even the client-side backstop
    /// would narrow it back down. (`&&` / `||` are not in the ss grammar; the
    /// spellings are `and` / `or`.)
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut rest = input.trim();
        // winnow's error carries no context: say where it stopped.
        let expr = parse_or_expr(&mut rest).map_err(|_| {
            format!("filter parse error: cannot read `{}` in `{input}`", rest.trim())
        })?;
        let rest = rest.trim();
        if !rest.is_empty() {
            return Err(format!(
                "filter parse error: unexpected trailing input `{rest}` \
                 (operators are `and` / `or` / `not`)"
            ));
        }
        Ok(expr)
    }

    /// Evaluate this expression against a socket.
    ///
    /// Every predicate in the grammar (`sport`/`dport`/`src`/`dst`/
    /// `state`) reads inet-socket fields, so a port/address/state
    /// expression is inherently inet-only. A non-inet socket cannot
    /// satisfy it and is therefore excluded — matching the
    /// `InetMatch` behaviour the `ss` binary applies to
    /// `--sport`/`--dport`/`--src`/`--dst`. (Previously non-inet
    /// sockets passed through unconditionally, so `ss -x 'sport = :22'`
    /// kept every unix socket — issue #20.)
    pub fn matches_socket_info(&self, socket: &SocketInfo) -> bool {
        match socket {
            SocketInfo::Inet(inet) => self.matches(inet),
            _ => false,
        }
    }

    /// Evaluate this expression against an inet socket.
    pub fn matches(&self, socket: &InetSocket) -> bool {
        match self {
            Self::Sport(cmp, port) => cmp.apply(socket.local.port(), *port),
            Self::Dport(cmp, port) => cmp.apply(socket.remote.port(), *port),
            Self::Src(addr, prefix_len) => ip_matches(&socket.local.ip(), addr, *prefix_len),
            Self::Dst(addr, prefix_len) => ip_matches(&socket.remote.ip(), addr, *prefix_len),
            Self::State(state) => socket.state == *state,
            Self::And(a, b) => a.matches(socket) && b.matches(socket),
            Self::Or(a, b) => a.matches(socket) || b.matches(socket),
            Self::Not(inner) => !inner.matches(socket),
        }
    }
}

/// Does `socket_ip` fall inside `filter_ip/prefix_len`?
///
/// `prefix_len == 0` is the "any address" prefix and must match everything —
/// note the mask is built by an explicit zero-case, not by shifting. Shifting
/// a `u32` by 32 is not "shift everything out": Rust panics in debug and masks
/// the shift count in release (`32 & 31 == 0`), which would have turned `/0`
/// into an *exact* address match — the reverse of what it means (#204).
fn ip_matches(socket_ip: &IpAddr, filter_ip: &IpAddr, prefix_len: u8) -> bool {
    match (socket_ip, filter_ip) {
        (IpAddr::V4(sock), IpAddr::V4(filter)) => {
            if prefix_len >= 32 {
                return sock == filter;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (u32::from(*sock) & mask) == (u32::from(*filter) & mask)
        }
        (IpAddr::V6(sock), IpAddr::V6(filter)) => {
            if prefix_len >= 128 {
                return sock == filter;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (u128::from(*sock) & mask) == (u128::from(*filter) & mask)
        }
        _ => false,
    }
}

// Parser implementation using winnow

type PResult<T> = Result<T, ErrMode<ContextError>>;

fn parse_or_expr(input: &mut &str) -> PResult<FilterExpr> {
    let mut left = parse_and_expr(input)?;
    loop {
        let _ = multispace0.parse_next(input)?;
        // `or(` is accepted alongside `or ` — a parenthesized right operand
        // needs no separating space.
        if input.starts_with("or ") || input.starts_with("or\t") || input.starts_with("or(") {
            let _ = "or".parse_next(input)?;
            // multispace0, not multispace1: the `or(` form has no space. The
            // starts_with guard above already established the delimiter, so
            // this cannot swallow an identifier like `orange`.
            let _ = multispace0.parse_next(input)?;
            let right = parse_and_expr(input)?;
            left = FilterExpr::Or(Box::new(left), Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_and_expr(input: &mut &str) -> PResult<FilterExpr> {
    let mut left = parse_unary_expr(input)?;
    loop {
        let _ = multispace0.parse_next(input)?;
        if input.starts_with("and ") || input.starts_with("and\t") || input.starts_with("and(") {
            let _ = "and".parse_next(input)?;
            let _ = multispace0.parse_next(input)?;
            let right = parse_unary_expr(input)?;
            left = FilterExpr::And(Box::new(left), Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_unary_expr(input: &mut &str) -> PResult<FilterExpr> {
    let _ = multispace0.parse_next(input)?;
    if input.starts_with("not ") || input.starts_with("not\t") || input.starts_with("not(") {
        let _ = "not".parse_next(input)?;
        let _ = multispace0.parse_next(input)?;
        let expr = parse_unary_expr(input)?;
        return Ok(FilterExpr::Not(Box::new(expr)));
    }
    if input.starts_with('!') {
        let _ = "!".parse_next(input)?;
        let _ = multispace0.parse_next(input)?;
        let expr = parse_unary_expr(input)?;
        return Ok(FilterExpr::Not(Box::new(expr)));
    }
    parse_primary(input)
}

fn parse_primary(input: &mut &str) -> PResult<FilterExpr> {
    let _ = multispace0.parse_next(input)?;

    // Parenthesized expression
    if input.starts_with('(') {
        let _ = "(".parse_next(input)?;
        let _ = multispace0.parse_next(input)?;
        let expr = parse_or_expr(input)?;
        let _ = multispace0.parse_next(input)?;
        let _ = ")".parse_next(input)?;
        return Ok(expr);
    }

    // sport/dport comparison
    if input.starts_with("sport") || input.starts_with("dport") {
        return parse_port_expr(input);
    }

    // src/dst host condition
    if input.starts_with("src") {
        let _ = "src".parse_next(input)?;
        let _ = multispace1.parse_next(input)?;
        return parse_hostcond(input, true);
    }
    if input.starts_with("dst") {
        let _ = "dst".parse_next(input)?;
        let _ = multispace1.parse_next(input)?;
        return parse_hostcond(input, false);
    }

    // state match
    if input.starts_with("state") {
        let _ = "state".parse_next(input)?;
        let _ = multispace1.parse_next(input)?;
        let state = parse_state(input)?;
        return Ok(FilterExpr::State(state));
    }

    Err(ErrMode::Cut(ContextError::new()))
}

fn parse_port_expr(input: &mut &str) -> PResult<FilterExpr> {
    let is_sport = input.starts_with("sport");
    if is_sport {
        let _ = "sport".parse_next(input)?;
    } else {
        let _ = "dport".parse_next(input)?;
    }
    let _ = multispace0.parse_next(input)?;

    let cmp = parse_comparison(input)?;
    let _ = multispace0.parse_next(input)?;

    let port = parse_port_value(input)?;

    if is_sport {
        Ok(FilterExpr::Sport(cmp, port))
    } else {
        Ok(FilterExpr::Dport(cmp, port))
    }
}

fn parse_comparison(input: &mut &str) -> PResult<Comparison> {
    let _ = multispace0.parse_next(input)?;

    // Try symbolic operators first
    if input.starts_with("!=") {
        let _ = "!=".parse_next(input)?;
        return Ok(Comparison::Ne);
    }
    if input.starts_with(">=") {
        let _ = ">=".parse_next(input)?;
        return Ok(Comparison::Ge);
    }
    if input.starts_with("<=") {
        let _ = "<=".parse_next(input)?;
        return Ok(Comparison::Le);
    }
    if input.starts_with('=') {
        let _ = "=".parse_next(input)?;
        return Ok(Comparison::Eq);
    }
    if input.starts_with('>') {
        let _ = ">".parse_next(input)?;
        return Ok(Comparison::Gt);
    }
    if input.starts_with('<') {
        let _ = "<".parse_next(input)?;
        return Ok(Comparison::Lt);
    }

    // Word operators
    let word: &str = take_while(2..=3, |c: char| c.is_ascii_alphabetic()).parse_next(input)?;
    match word {
        "eq" => Ok(Comparison::Eq),
        "ne" => Ok(Comparison::Ne),
        "lt" => Ok(Comparison::Lt),
        "le" => Ok(Comparison::Le),
        "gt" => Ok(Comparison::Gt),
        "ge" => Ok(Comparison::Ge),
        _ => Err(ErrMode::Cut(ContextError::new())),
    }
}

fn parse_port_value(input: &mut &str) -> PResult<u16> {
    // Optional colon prefix (ss syntax: `:22`)
    let _ = opt(":").parse_next(input)?;
    let digits: &str = digit1.parse_next(input)?;
    digits
        .parse::<u16>()
        .map_err(|_| ErrMode::Cut(ContextError::new()))
}

/// An ss(8) host condition, as its `parse_hostcond()` reads one (#838):
/// `ADDR[/PREFIX][:PORT]`, `[ADDR[/PREFIX]][:PORT]` or `*[:PORT]`, where
/// the port follows the last `:` past any `/`. A bare IPv6 address, which
/// ss would split at its last colon, reads whole. A port folds in as
/// `sport`/`dport = :PORT`, which is what ss matches it as.
fn parse_hostcond(input: &mut &str, is_src: bool) -> PResult<FilterExpr> {
    let cut = || ErrMode::Cut(ContextError::new());
    let token: &str = take_while(1.., |c: char| !c.is_whitespace() && c != '(' && c != ')').parse_next(input)?;
    // What follows an address: nothing, or `:PORT`.
    fn tail(after: &str) -> PResult<Option<&str>> {
        match after {
            "" => Ok(None),
            p => p.strip_prefix(':').map(Some).ok_or_else(|| ErrMode::Cut(ContextError::new())),
        }
    }
    let bare_v6 = |t: &str| t.split_once('/').map_or(t, |(a, _)| a).parse::<std::net::Ipv6Addr>().is_ok();
    let (addr, port) = if let Some(rest) = token.strip_prefix('[') {
        let (addr, after) = rest.split_once(']').ok_or_else(cut)?;
        (Some(addr), tail(after)?)
    } else if let Some(after) = token.strip_prefix('*') {
        (None, tail(after)?)
    } else if bare_v6(token) {
        (Some(token), None)
    } else {
        let from = token.find('/').unwrap_or(0);
        match token[from..].rfind(':') {
            Some(at) => (Some(&token[..from + at]), Some(&token[from + at + 1..])),
            None => (Some(token), None),
        }
    };
    let addr = match addr.filter(|a| !a.is_empty() && *a != "*") {
        Some(a) => {
            let (ip, prefix) = a.split_once('/').map_or((a, None), |(ip, p)| (ip, Some(p)));
            let ip: IpAddr = ip.parse().map_err(|_| cut())?;
            let prefix = match prefix {
                Some(p) => p.parse::<u8>().map_err(|_| cut())?,
                None if ip.is_ipv4() => 32,
                None => 128,
            };
            Some((ip, prefix))
        }
        None => None,
    };
    let port = match port.filter(|p| !p.is_empty() && *p != "*") {
        Some(p) => Some(p.parse::<u16>().map_err(|_| cut())?),
        None => None,
    };
    let host = addr.map(|(ip, prefix)| if is_src { FilterExpr::Src(ip, prefix) } else { FilterExpr::Dst(ip, prefix) });
    let port = port.map(|p| if is_src { FilterExpr::Sport(Comparison::Eq, p) } else { FilterExpr::Dport(Comparison::Eq, p) });
    match (host, port) {
        (Some(h), Some(p)) => Ok(FilterExpr::And(Box::new(h), Box::new(p))),
        (Some(e), None) | (None, Some(e)) => Ok(e),
        // `*` alone matches every socket: nothing to filter on.
        (None, None) => Err(cut()),
    }
}

fn parse_state(input: &mut &str) -> PResult<SocketState> {
    let word: &str = take_while(1.., |c: char| {
        c.is_ascii_alphanumeric() || c == '-' || c == '_'
    })
    .parse_next(input)?;
    match word.to_ascii_lowercase().as_str() {
        "established" | "estab" => Ok(SocketState::Tcp(TcpState::Established)),
        "syn-sent" | "syn_sent" => Ok(SocketState::Tcp(TcpState::SynSent)),
        "syn-recv" | "syn_recv" => Ok(SocketState::Tcp(TcpState::SynRecv)),
        "fin-wait-1" | "fin_wait_1" | "fin-wait1" => Ok(SocketState::Tcp(TcpState::FinWait1)),
        "fin-wait-2" | "fin_wait_2" | "fin-wait2" => Ok(SocketState::Tcp(TcpState::FinWait2)),
        "time-wait" | "time_wait" | "timewait" => Ok(SocketState::Tcp(TcpState::TimeWait)),
        "close" | "closed" => Ok(SocketState::Tcp(TcpState::Close)),
        "close-wait" | "close_wait" => Ok(SocketState::Tcp(TcpState::CloseWait)),
        "last-ack" | "last_ack" => Ok(SocketState::Tcp(TcpState::LastAck)),
        "listening" | "listen" => Ok(SocketState::Tcp(TcpState::Listen)),
        "closing" => Ok(SocketState::Tcp(TcpState::Closing)),
        _ => Err(ErrMode::Cut(ContextError::new())),
    }
}

#[cfg(test)]
mod tests {

    /// ss(8)'s host conditions: `[v6]`, `addr:port`, `*:port` (#838).
    #[test]
    fn host_conditions_read_as_ss_reads_them() {
        let show = |s: &str| format!("{:?}", FilterExpr::parse(s).unwrap());
        assert_eq!(show("src [::1]"), show("src ::1"));
        assert_eq!(show("src 127.0.0.1:8001"), show("src 127.0.0.1 and sport = :8001"));
        assert_eq!(show("dst [fd00::/64]:443"), show("dst fd00::/64 and dport = :443"));
        assert_eq!(show("src 10.0.0.0/8:22"), show("src 10.0.0.0/8 and sport = :22"));
        assert_eq!(show("src *:22"), show("sport = :22"));
        assert_eq!(show("src 10.0.0.1:*"), show("src 10.0.0.1"));
        for bad in ["src *", "src [::1", "src [::1]x", "src 10.0.0.1:http", "src 10.0.0.300"] {
            let err = FilterExpr::parse(bad).unwrap_err();
            assert!(err.contains("cannot read"), "{bad}: {err}");
        }
    }

    use std::net::SocketAddr;

    use super::*;
    use crate::sockdiag::types::{AddressFamily, Protocol, Timer};

    fn tcp_state(state: TcpState) -> SocketState {
        SocketState::Tcp(state)
    }

    fn make_socket(local: &str, remote: &str, state: SocketState) -> InetSocket {
        InetSocket {
            family: AddressFamily::Inet,
            protocol: Protocol::Tcp,
            state,
            local: local.parse::<SocketAddr>().unwrap(),
            remote: remote.parse::<SocketAddr>().unwrap(),
            interface: 0,
            cookie: 0,
            timer: Timer::Off,
            recv_q: 0,
            send_q: 0,
            uid: 0,
            inode: 0,
            refcnt: 0,
            mark: None,
            cgroup_id: None,
            tcp_info: None,
            mem_info: None,
            congestion: None,
            cc_info: None,
            tos: None,
            tclass: None,
            shutdown: None,
            v6only: None,
        }
    }

    #[test]
    fn parse_sport_eq() {
        let expr = FilterExpr::parse("sport = :22").unwrap();
        let sock = make_socket("0.0.0.0:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(expr.matches(&sock));
        let sock2 = make_socket("0.0.0.0:80", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(!expr.matches(&sock2));
    }

    #[test]
    fn parse_dport_ne() {
        let expr = FilterExpr::parse("dport != :80").unwrap();
        let sock = make_socket(
            "0.0.0.0:12345",
            "10.0.0.1:443",
            tcp_state(TcpState::Established),
        );
        assert!(expr.matches(&sock));
        let sock2 = make_socket(
            "0.0.0.0:12345",
            "10.0.0.1:80",
            tcp_state(TcpState::Established),
        );
        assert!(!expr.matches(&sock2));
    }

    #[test]
    fn parse_sport_gt() {
        let expr = FilterExpr::parse("sport > :1024").unwrap();
        let sock = make_socket("0.0.0.0:8080", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(expr.matches(&sock));
        let sock2 = make_socket("0.0.0.0:80", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(!expr.matches(&sock2));
    }

    #[test]
    fn parse_state_match() {
        let expr = FilterExpr::parse("state established").unwrap();
        let sock = make_socket(
            "0.0.0.0:22",
            "10.0.0.1:5000",
            tcp_state(TcpState::Established),
        );
        assert!(expr.matches(&sock));
        let sock2 = make_socket("0.0.0.0:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(!expr.matches(&sock2));
    }

    #[test]
    fn parse_state_aliases() {
        assert!(FilterExpr::parse("state estab").is_ok());
        assert!(FilterExpr::parse("state listening").is_ok());
        assert!(FilterExpr::parse("state time-wait").is_ok());
        assert!(FilterExpr::parse("state fin-wait-1").is_ok());
        assert!(FilterExpr::parse("state close-wait").is_ok());
    }

    #[test]
    fn parse_dst_prefix() {
        let expr = FilterExpr::parse("dst 192.168.0.0/16").unwrap();
        let sock = make_socket(
            "0.0.0.0:22",
            "192.168.1.100:5000",
            tcp_state(TcpState::Established),
        );
        assert!(expr.matches(&sock));
        let sock2 = make_socket(
            "0.0.0.0:22",
            "10.0.0.1:5000",
            tcp_state(TcpState::Established),
        );
        assert!(!expr.matches(&sock2));
    }

    #[test]
    fn parse_src_exact() {
        let expr = FilterExpr::parse("src 10.0.0.1").unwrap();
        let sock = make_socket("10.0.0.1:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(expr.matches(&sock));
        let sock2 = make_socket("10.0.0.2:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(!expr.matches(&sock2));
    }

    #[test]
    fn parse_and() {
        let expr = FilterExpr::parse("sport = :22 and state established").unwrap();
        let sock = make_socket(
            "0.0.0.0:22",
            "10.0.0.1:5000",
            tcp_state(TcpState::Established),
        );
        assert!(expr.matches(&sock));
        let sock2 = make_socket("0.0.0.0:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(!expr.matches(&sock2));
    }

    #[test]
    fn parse_or() {
        let expr = FilterExpr::parse("sport = :22 or sport = :443").unwrap();
        let sock22 = make_socket("0.0.0.0:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        let sock443 = make_socket("0.0.0.0:443", "0.0.0.0:0", tcp_state(TcpState::Listen));
        let sock80 = make_socket("0.0.0.0:80", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(expr.matches(&sock22));
        assert!(expr.matches(&sock443));
        assert!(!expr.matches(&sock80));
    }

    #[test]
    fn parse_not() {
        let expr = FilterExpr::parse("not state listening").unwrap();
        let sock = make_socket(
            "0.0.0.0:22",
            "10.0.0.1:5000",
            tcp_state(TcpState::Established),
        );
        assert!(expr.matches(&sock));
        let sock2 = make_socket("0.0.0.0:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(!expr.matches(&sock2));
    }

    #[test]
    fn parse_parens() {
        let expr =
            FilterExpr::parse("( sport = :80 or sport = :443 ) and state listening").unwrap();
        let sock80 = make_socket("0.0.0.0:80", "0.0.0.0:0", tcp_state(TcpState::Listen));
        let sock443 = make_socket("0.0.0.0:443", "0.0.0.0:0", tcp_state(TcpState::Listen));
        let sock22 = make_socket("0.0.0.0:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        let sock80_est = make_socket(
            "0.0.0.0:80",
            "10.0.0.1:5000",
            tcp_state(TcpState::Established),
        );
        assert!(expr.matches(&sock80));
        assert!(expr.matches(&sock443));
        assert!(!expr.matches(&sock22));
        assert!(!expr.matches(&sock80_est));
    }

    #[test]
    fn parse_word_operators() {
        let expr = FilterExpr::parse("sport eq :22").unwrap();
        let sock = make_socket("0.0.0.0:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(expr.matches(&sock));
    }

    #[test]
    fn parse_port_without_colon() {
        let expr = FilterExpr::parse("sport = 22").unwrap();
        let sock = make_socket("0.0.0.0:22", "0.0.0.0:0", tcp_state(TcpState::Listen));
        assert!(expr.matches(&sock));
    }

    #[test]
    fn parse_error() {
        assert!(FilterExpr::parse("").is_err());
        assert!(FilterExpr::parse("invalid").is_err());
        assert!(FilterExpr::parse("sport = :abc").is_err());
    }

    #[test]
    fn non_inet_excluded_by_inet_expr() {
        use crate::sockdiag::socket::{SocketInfo, UnixSocket, UnixType};

        // An inet port/addr/state expression cannot match a non-inet
        // socket — it must be excluded, not passed through (issue #20:
        // `ss -x 'sport = :22'` previously kept every unix socket).
        let expr = FilterExpr::parse("sport = :22").unwrap();
        let unix = SocketInfo::Unix(UnixSocket::new(
            UnixType::Stream,
            SocketState::Tcp(TcpState::Established),
            42,
        ));
        assert!(!expr.matches_socket_info(&unix));

        // Inet sockets still evaluate normally.
        let inet = SocketInfo::Inet(Box::new(make_socket(
            "0.0.0.0:22",
            "0.0.0.0:0",
            tcp_state(TcpState::Listen),
        )));
        assert!(expr.matches_socket_info(&inet));
    }

    // ----------------------------------------------------------------
    // #204 — /0 is the "any address" prefix, not a shift overflow.
    // ----------------------------------------------------------------

    /// `src 0.0.0.0/0` matches every v4 socket.
    ///
    /// The old mask was `u32::MAX << (32 - 0)`, i.e. a shift by the full
    /// width: a **panic** in debug, and in release a shift count masked to 0
    /// — leaving `mask = u32::MAX`, which turned "any address" into an exact
    /// match on `0.0.0.0` and returned nothing. This test runs in debug in
    /// CI, so it pins both halves.
    #[test]
    fn a_zero_length_v4_prefix_matches_everything() {
        let expr = FilterExpr::parse("src 0.0.0.0/0").unwrap();
        for ip in ["10.1.2.3:22", "192.168.0.1:443", "0.0.0.0:0"] {
            let sock = make_socket(ip, "0.0.0.0:0", tcp_state(TcpState::Listen));
            assert!(expr.matches(&sock), "src 0.0.0.0/0 must match {ip}");
        }
    }

    #[test]
    fn a_zero_length_v6_prefix_matches_everything() {
        let expr = FilterExpr::parse("src ::/0").unwrap();
        for ip in ["[2001:db8::1]:22", "[::1]:443", "[::]:0"] {
            let sock = make_socket(ip, "[::]:0", tcp_state(TcpState::Listen));
            assert!(expr.matches(&sock), "src ::/0 must match {ip}");
        }
    }

    /// The other boundary: a full-width prefix is an exact match.
    #[test]
    fn a_full_length_prefix_is_an_exact_match() {
        let expr = FilterExpr::parse("src 10.1.2.3/32").unwrap();
        assert!(expr.matches(&make_socket(
            "10.1.2.3:22",
            "0.0.0.0:0",
            tcp_state(TcpState::Listen)
        )));
        assert!(!expr.matches(&make_socket(
            "10.1.2.4:22",
            "0.0.0.0:0",
            tcp_state(TcpState::Listen)
        )));

        let expr = FilterExpr::parse("src ::1/128").unwrap();
        assert!(expr.matches(&make_socket(
            "[::1]:22",
            "[::]:0",
            tcp_state(TcpState::Listen)
        )));
        assert!(!expr.matches(&make_socket(
            "[::2]:22",
            "[::]:0",
            tcp_state(TcpState::Listen)
        )));
    }

    // ----------------------------------------------------------------
    // #224 — the whole input must be consumed.
    // ----------------------------------------------------------------

    /// Trailing input is an error, not a stopping point.
    ///
    /// Each of these used to parse as its *first* conjunct alone and return
    /// `Ok` — a strictly larger set of sockets than was asked for, and marked
    /// exact, so the client-side backstop would not narrow it either.
    #[test]
    fn trailing_input_is_rejected() {
        for bad in [
            "sport = :22 && dport = :80",
            "dport = :443 garbage",
            "sport = :22 ) extra",
            "src 10.0.0.0/8 || dst 10.0.0.1",
        ] {
            let err = FilterExpr::parse(bad)
                .expect_err("`{bad}` must not parse to a weaker filter than written");
            assert!(
                err.contains("trailing input"),
                "expected a trailing-input error for `{bad}`, got: {err}"
            );
        }
    }

    /// `or(` / `and(` — a parenthesized operand needs no separating space.
    #[test]
    fn operators_accept_a_parenthesized_operand_without_a_space() {
        // FilterExpr has no PartialEq; the Debug shape is the AST.
        for (compact, spaced) in [
            ("sport = :22 or(dport = :80)", "sport = :22 or dport = :80"),
            ("sport = :22 and(dport = :80)", "sport = :22 and dport = :80"),
        ] {
            assert_eq!(
                format!("{:?}", FilterExpr::parse(compact).unwrap()),
                format!("{:?}", FilterExpr::parse(spaced).unwrap()),
                "`{compact}` must parse the same as `{spaced}`"
            );
        }
    }
}
