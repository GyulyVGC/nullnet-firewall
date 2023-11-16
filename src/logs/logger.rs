use crate::LogEntry;
use rusqlite::{Connection};
use std::sync::mpsc::Receiver;

struct Logger {
    db: Connection,
    batch: Vec<LogEntry>,
    batch_size: u32,
}

impl Logger {
    fn new(batch_size: u32) -> Logger {
        Logger {
            db: Connection::open("./log.sqlite").unwrap(),
            batch: Vec::new(),
            batch_size,
        }
    }

    fn create_table(&self) {
        self.db
            .execute(
                "CREATE TABLE IF NOT EXISTS traffic (
            id        INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            direction TEXT NOT NULL,
            action    TEXT NOT NULL,
            proto     TEXT,
            source    TEXT,
            dest      TEXT,
            sport     INTEGER,
            dport     INTEGER,
            icmptype  TEXT,
            size      INTEGER NOT NULL
        )",
                (),
            )
            .unwrap();
    }

    fn add_entry(&self, log_entry: LogEntry) {
        self.db.execute(
            "INSERT INTO traffic (timestamp, direction, action, proto, source, dest, sport, dport, icmptype, size)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            (&log_entry.timestamp.to_string(), &log_entry.direction, &log_entry.action,
             &log_entry.proto, log_entry.source, log_entry.dest, &log_entry.sport,
             &log_entry.dport, &log_entry.icmp_type, &log_entry.size),
        ).unwrap();
    }
}

pub(crate) fn log(rx: &Receiver<LogEntry>) {
    let logger = Logger::new(10);
    logger.create_table();

    loop {
        let log_entry = rx.recv().expect("channel is down");

        // log into console
        println!("{log_entry}");

        // log into db
        logger.add_entry(log_entry);
    }
}
