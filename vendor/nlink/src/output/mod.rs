//! Output formatting (JSON/text) for nlink.

pub mod formatting;
mod json;
pub mod monitor;
mod printable;
mod text;

use std::io::Write;

pub use formatting::{
    format_bytes, format_duration, format_duration_compact, format_hex, format_ipv4, format_mac,
    format_percent, format_rate_bps, format_rate_bytes, format_tc_handle, format_time_ago,
};
// `pub` items in a private module: visible in rustdoc, unnameable
// downstream (#280).
pub use json::{JsonBuilder, JsonOutput};
pub use monitor::{
    AddressEvent, IpEvent, LinkEvent, MonitorConfig, MonitorEvent, NeighborEvent, RouteEvent,
    TcEvent, print_event, print_monitor_start, write_timestamp,
};
pub use text::{TextOutput, format_number, format_rate};

/// Output format options.
///
/// **Who honours what.** The formatters this module ships read `pretty`
/// (JSON indentation) and `stats`. The other three are carried for the
/// *renderer* — `Printable` is implemented downstream, and the `bins/`
/// read them there: `nlink-bridge` uses `details` to surface raw NUD
/// state, `nlink-ss` uses `numeric` to skip name resolution, and the
/// `bins/` set `color` from `IsTerminal`.
///
/// The field docs used to read as library behaviour, so `color: true`
/// looked like it would emit ANSI and `numeric: true` like it would stop
/// resolving names — neither of which anything in this module does
/// (#276). They are options a renderer is handed, not options this
/// module acts on.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutputOptions {
    /// Show detailed statistics. Read by the shipped TC formatter.
    pub stats: bool,
    /// Show extra details. For the renderer to honour; nothing in this
    /// module reads it.
    pub details: bool,
    /// Use colored output. For the renderer to honour; nothing in this
    /// module emits ANSI.
    pub color: bool,
    /// Don't resolve names (show numeric values). For the renderer to
    /// honour; nothing in this module resolves names.
    pub numeric: bool,
    /// Pretty print (for JSON). Read by the shipped JSON formatter.
    pub pretty: bool,
}

/// Output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Plain text output.
    #[default]
    Text,
    /// JSON output.
    Json,
}

/// Trait for types that can be printed.
pub trait Printable {
    /// Print as plain text.
    fn print_text<W: Write>(&self, w: &mut W, opts: &OutputOptions) -> std::io::Result<()>;

    /// Convert to JSON value.
    fn to_json(&self) -> serde_json::Value;

    /// Print in the specified format.
    fn print<W: Write>(
        &self,
        w: &mut W,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> std::io::Result<()> {
        match format {
            OutputFormat::Text => self.print_text(w, opts),
            OutputFormat::Json => {
                let json = self.to_json();
                if opts.pretty {
                    serde_json::to_writer_pretty(&mut *w, &json)?;
                } else {
                    serde_json::to_writer(&mut *w, &json)?;
                }
                writeln!(w)?;
                Ok(())
            }
        }
    }
}

/// Trait for collections of printable items.
pub trait PrintableList {
    /// The item type.
    type Item: Printable;

    /// Get the items.
    fn items(&self) -> &[Self::Item];

    /// Print all items as text.
    fn print_text<W: Write>(&self, w: &mut W, opts: &OutputOptions) -> std::io::Result<()> {
        for item in self.items() {
            item.print_text(w, opts)?;
        }
        Ok(())
    }

    /// Convert to JSON array.
    fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Array(self.items().iter().map(|item| item.to_json()).collect())
    }

    /// Print in the specified format.
    fn print<W: Write>(
        &self,
        w: &mut W,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> std::io::Result<()> {
        match format {
            OutputFormat::Text => self.print_text(w, opts),
            OutputFormat::Json => {
                let json = self.to_json();
                if opts.pretty {
                    serde_json::to_writer_pretty(&mut *w, &json)?;
                } else {
                    serde_json::to_writer(&mut *w, &json)?;
                }
                writeln!(w)?;
                Ok(())
            }
        }
    }
}

/// Print a list of Printable items to stdout.
///
/// This is the simplest way to print items that implement the `Printable` trait.
/// For types with custom Printable implementations (LinkMessage, RouteMessage, etc.),
/// this eliminates the need for separate print functions.
///
/// # Example
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::LinkMessage;
/// # use nlink::netlink::NlMsgType;
/// # use nlink::output::print_all;
/// # use nlink::output::{OutputFormat, OutputOptions};
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// # let opts = OutputOptions::default();
/// let links: Vec<LinkMessage> = conn.dump_typed(NlMsgType::RTM_GETLINK).await?;
/// print_all(&links, OutputFormat::Text, &opts)?;
/// # Ok(())
/// # }
/// ```
pub fn print_all<T: Printable>(
    items: &[T],
    format: OutputFormat,
    opts: &OutputOptions,
) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    match format {
        OutputFormat::Text => {
            for item in items {
                item.print_text(&mut stdout, opts)?;
            }
        }
        OutputFormat::Json => {
            let json: Vec<_> = items.iter().map(|i| i.to_json()).collect();
            if opts.pretty {
                serde_json::to_writer_pretty(&mut stdout, &json)?;
            } else {
                serde_json::to_writer(&mut stdout, &json)?;
            }
            writeln!(stdout)?;
        }
    }
    Ok(())
}

/// Print a list of items in the specified format.
///
/// This helper reduces boilerplate in command files by providing a single
/// function that handles both text and JSON output formats.
///
/// # Arguments
/// * `items` - The items to print
/// * `format` - The output format (Text or Json)
/// * `opts` - Output options
/// * `to_json` - Function to convert an item to JSON
/// * `print_text` - Function to print an item as text
///
/// # Example
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use std::io::Write;
/// # use nlink::output::{OutputFormat, OutputOptions, print_items};
/// # let links: Vec<u32> = Vec::new();
/// # let opts = OutputOptions::default();
/// print_items(
///     &links,
///     OutputFormat::Text,
///     &opts,
///     |item| serde_json::json!(item),
///     |w, item, _opts| writeln!(w, "{item}"),
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// Note: For types implementing `Printable`, prefer using `print_all()` instead.
/// This function is still useful for types with custom output formats.
pub fn print_items<T, J, P>(
    items: &[T],
    format: OutputFormat,
    opts: &OutputOptions,
    to_json: J,
    print_text: P,
) -> std::io::Result<()>
where
    J: Fn(&T) -> serde_json::Value,
    P: Fn(&mut std::io::StdoutLock<'_>, &T, &OutputOptions) -> std::io::Result<()>,
{
    let mut stdout = std::io::stdout().lock();
    match format {
        OutputFormat::Text => {
            for item in items {
                print_text(&mut stdout, item, opts)?;
            }
        }
        OutputFormat::Json => {
            let json: Vec<_> = items.iter().map(&to_json).collect();
            if opts.pretty {
                serde_json::to_writer_pretty(&mut stdout, &json)?;
            } else {
                serde_json::to_writer(&mut stdout, &json)?;
            }
            writeln!(stdout)?;
        }
    }
    Ok(())
}

/// Print a list of items to a custom writer in the specified format.
///
/// Same as `print_items` but allows specifying a custom writer instead of stdout.
pub fn print_items_to<W, T, J, P>(
    writer: &mut W,
    items: &[T],
    format: OutputFormat,
    opts: &OutputOptions,
    to_json: J,
    print_text: P,
) -> std::io::Result<()>
where
    W: Write,
    J: Fn(&T) -> serde_json::Value,
    P: Fn(&mut W, &T, &OutputOptions) -> std::io::Result<()>,
{
    match format {
        OutputFormat::Text => {
            for item in items {
                print_text(writer, item, opts)?;
            }
        }
        OutputFormat::Json => {
            let json: Vec<_> = items.iter().map(&to_json).collect();
            if opts.pretty {
                serde_json::to_writer_pretty(&mut *writer, &json)?;
            } else {
                serde_json::to_writer(&mut *writer, &json)?;
            }
            writeln!(writer)?;
        }
    }
    Ok(())
}

/// Helper for building text output.
pub struct OutputBuilder<W: Write> {
    writer: W,
    indent: usize,
}

impl<W: Write> OutputBuilder<W> {
    /// Create a new output builder.
    pub fn new(writer: W) -> Self {
        Self { writer, indent: 0 }
    }

    /// Increase indentation.
    pub fn indent(&mut self) {
        self.indent += 4;
    }

    /// Decrease indentation.
    pub fn dedent(&mut self) {
        self.indent = self.indent.saturating_sub(4);
    }

    /// Write indentation.
    pub fn write_indent(&mut self) -> std::io::Result<()> {
        for _ in 0..self.indent {
            write!(self.writer, " ")?;
        }
        Ok(())
    }

    /// Write a line with indentation.
    pub fn writeln(&mut self, s: &str) -> std::io::Result<()> {
        self.write_indent()?;
        writeln!(self.writer, "{}", s)
    }

    /// Write without newline.
    pub fn write(&mut self, s: &str) -> std::io::Result<()> {
        write!(self.writer, "{}", s)
    }

    /// Write a key-value pair.
    pub fn write_kv(&mut self, key: &str, value: &str) -> std::io::Result<()> {
        write!(self.writer, "{} {} ", key, value)
    }

    /// Write a newline.
    pub fn newline(&mut self) -> std::io::Result<()> {
        writeln!(self.writer)
    }

    /// Get the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}
