use crate::logs::log_entry::format_ip_address;
use crate::LogEntry;
use rusqlite::Connection;
use std::sync::mpsc::Receiver;

// struct Logger {
//     db_batch
// }

const DB_PATH: &str = "./log.sqlite";

pub(crate) fn log(rx: &Receiver<LogEntry>) {
    let db = Connection::open(DB_PATH).unwrap();
    db.execute(
        "CREATE TABLE IF NOT EXISTS traffic (
            id        INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            direction TEXT NOT NULL,
            action    TEXT NOT NULL,
            proto     TEXT,
            source    TEXT,
            dest      TEXT,
            sport     TEXT,
            dport     TEXT,
            icmptype TEXT,
            size      INTEGER NOT NULL
        )",
        (),
    )
    .unwrap();

    loop {
        let log_entry = rx.recv().expect("channel is down");

        // log into console
        println!("{log_entry}");

        // log into db
        db.execute(
            "INSERT INTO traffic (timestamp, direction, action, proto, source, dest, sport, dport, icmp-type, size)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            (&log_entry.timestamp.to_string(), &log_entry.direction, &log_entry.action, &log_entry.fields.proto,
            format_ip_address(log_entry.fields.source), format_ip_address(log_entry.fields.dest),
            &log_entry.fields.sport, &log_entry.fields.dport, &log_entry.fields.icmp_type, &log_entry.fields.size),
        ).unwrap();
    }
}
