use crate::LogEntry;
use std::sync::mpsc::Receiver;

pub(crate) fn log(rx: &Receiver<LogEntry>) {
    loop {
        let log_entry = rx.recv().expect("channel is down");
        println!("{log_entry}");
    }
}
