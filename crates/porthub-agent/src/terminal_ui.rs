//! Shared terminal lifecycle and cancellable keyboard input for CLI dashboards.
use anyhow::Result;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(crate) struct InputReader {
    stop: CancellationToken,
    task: Option<std::thread::JoinHandle<()>>,
}
impl InputReader {
    pub(crate) fn start() -> (
        Self,
        tokio::sync::mpsc::Receiver<std::io::Result<crossterm::event::Event>>,
    ) {
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let (send, receive) = tokio::sync::mpsc::channel(32);
        let runtime = tokio::runtime::Handle::current();
        let task = std::thread::spawn(move || {
            while !stopped.is_cancelled() {
                let event = match crossterm::event::poll(Duration::from_millis(100)) {
                    Ok(false) => continue,
                    Ok(true) => crossterm::event::read(),
                    Err(error) => Err(error),
                };
                let failed = event.is_err();
                let sent=runtime.block_on(async {tokio::select!{_=stopped.cancelled()=>false,result=send.send(event)=>result.is_ok()}});
                if !sent || failed {
                    break;
                }
            }
        });
        (
            Self {
                stop,
                task: Some(task),
            },
            receive,
        )
    }
}
impl Drop for InputReader {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

pub(crate) struct Screen;
impl Screen {
    pub(crate) fn enter() -> Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        if let Err(error) = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::EnterAlternateScreen,
            crossterm::cursor::Hide
        ) {
            let _ = crossterm::terminal::disable_raw_mode();
            return Err(error.into());
        }
        Ok(Self)
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::cursor::Show,
            crossterm::terminal::LeaveAlternateScreen
        );
        let _ = crossterm::terminal::disable_raw_mode();
    }
}
