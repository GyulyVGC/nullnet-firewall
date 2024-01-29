use std::sync::mpsc::Receiver;

use rusqlite::Connection;

use crate::log_level::LogLevel;
use crate::LogEntry;

struct Logger {
    db: Connection,
    batch: Vec<LogEntry>,
    batch_size: usize,
    console_entries: u128,
}

// should be in the order of thousands when used in production
const BATCH_SIZE: usize = 25;

#[cfg(not(test))]
const SQLITE_PATH: &str = "./log.sqlite";
#[cfg(test)]
const SQLITE_PATH: &str = "./test.sqlite";

impl Logger {
    fn new() -> Logger {
        Logger {
            db: Connection::open(SQLITE_PATH).unwrap(),
            batch: Vec::new(),
            batch_size: BATCH_SIZE,
            console_entries: 0,
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
            proto     INTEGER,
            source    TEXT,
            dest      TEXT,
            sport     INTEGER,
            dport     INTEGER,
            icmptype  INTEGER,
            size      INTEGER NOT NULL
        )",
                (),
            )
            .unwrap();
    }

    fn store_entry(&mut self, log_entry: LogEntry) {
        self.batch.push(log_entry);
        if self.batch.len() >= self.batch_size {
            // write the batch to the DB in a single transaction
            self.store_batch();
            self.batch = Vec::new();
        }
    }

    fn log_entry(&mut self, log_entry: LogEntry) {
        match log_entry.log_level {
            LogLevel::Db => self.store_entry(log_entry),
            LogLevel::Console => {
                println!("{log_entry}");
                self.console_entries = self.console_entries.wrapping_add(1);
            }
            LogLevel::All => {
                println!("{log_entry}");
                self.console_entries = self.console_entries.wrapping_add(1);
                self.store_entry(log_entry);
            }
            LogLevel::Off => {
                panic!("Don't send on the channel entries that don't require logging!")
            }
        }
    }

    fn store_batch(&mut self) {
        let transaction = self.db.transaction().unwrap();
        for log_entry in &self.batch {
            transaction.execute(
                "INSERT INTO traffic (timestamp, direction, action, proto, source, dest, sport, dport, icmptype, size)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                (&log_entry.timestamp, &log_entry.direction, &log_entry.action,
                 &log_entry.proto, &log_entry.source, &log_entry.dest, &log_entry.sport,
                 &log_entry.dport, &log_entry.icmp_type, &log_entry.size),
            ).unwrap();
        }
        transaction.commit().unwrap();
    }
}

pub(crate) fn log(rx: &Receiver<LogEntry>) {
    let mut logger = Logger::new();
    logger.create_table();

    loop {
        logger.log_entry(rx.recv().expect("channel is down"));
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rusqlite::types::{FromSql, FromSqlResult, ValueRef};
    use rusqlite::Connection;
    use serial_test::serial;

    use crate::log_level::LogLevel;
    use crate::logs::logger::{Logger, SQLITE_PATH};
    use crate::utils::raw_packets::test_packets::{ARP_PACKET, ICMPV6_PACKET, TCP_PACKET};
    use crate::{DataLink, Fields, FirewallAction, FirewallDirection, FirewallError, LogEntry};

    impl FromStr for FirewallAction {
        type Err = FirewallError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "ACCEPT" => Ok(Self::ACCEPT),
                "DENY" => Ok(Self::DENY),
                "REJECT" => Ok(Self::REJECT),
                x => Err(FirewallError::InvalidAction(0, x.to_owned())),
            }
        }
    }

    impl FromSql for FirewallAction {
        fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
            FromSqlResult::Ok(FirewallAction::from_str(value.as_str().unwrap()).unwrap())
        }
    }

    impl FromStr for FirewallDirection {
        type Err = FirewallError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "IN" => Ok(Self::IN),
                "OUT" => Ok(Self::OUT),
                x => Err(FirewallError::InvalidDirection(0, x.to_owned())),
            }
        }
    }

    impl FromSql for FirewallDirection {
        fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
            FromSqlResult::Ok(FirewallDirection::from_str(value.as_str().unwrap()).unwrap())
        }
    }

    fn drop_table(logger: &Logger) {
        logger
            .db
            .execute("DROP TABLE IF EXISTS traffic", ())
            .unwrap();
    }

    fn retrieve_all_packets(logger: &Logger) -> Vec<LogEntry> {
        let mut stmt = logger.db.prepare("SELECT * FROM traffic").unwrap();
        let query_result = stmt
            .query_map([], |row| {
                Ok(LogEntry {
                    // row.get(0) is the id
                    timestamp: row.get(1).unwrap(),
                    direction: row.get(2).unwrap(),
                    action: row.get(3).unwrap(),
                    source: row.get(5).unwrap(),
                    dest: row.get(6).unwrap(),
                    sport: row.get(7).unwrap(),
                    dport: row.get(8).unwrap(),
                    proto: row.get(4).unwrap(),
                    icmp_type: row.get(9).unwrap(),
                    size: row.get(10).unwrap(),
                    log_level: LogLevel::All,
                })
            })
            .unwrap();

        let mut packets = Vec::new();
        for row in query_result {
            packets.push(row.unwrap());
        }
        packets
    }

    #[test]
    #[serial(database_test)]
    fn test_logger_with_log_level_all() {
        let mut logger = Logger {
            db: Connection::open(SQLITE_PATH).unwrap(),
            batch: Vec::new(),
            batch_size: 1,
            console_entries: 0,
        };

        drop_table(&logger);
        logger.create_table();

        let tcp_entry = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
            LogLevel::All,
        );
        let icmpv6_entry = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::ACCEPT,
            LogLevel::All,
        );
        let arp_entry = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
            LogLevel::All,
        );

        logger.log_entry(tcp_entry.clone());
        logger.log_entry(icmpv6_entry.clone());
        logger.log_entry(arp_entry.clone());

        assert_eq!(logger.console_entries, 3);
        let packets = retrieve_all_packets(&logger);
        assert_eq!(packets.len(), 3);
        assert_eq!(*packets.get(0).unwrap(), tcp_entry);
        assert_eq!(*packets.get(1).unwrap(), icmpv6_entry);
        assert_eq!(*packets.get(2).unwrap(), arp_entry);
    }

    #[test]
    #[serial(database_test)]
    fn test_logger_with_log_level_db() {
        let mut logger = Logger {
            db: Connection::open(SQLITE_PATH).unwrap(),
            batch: Vec::new(),
            batch_size: 1,
            console_entries: 0,
        };

        drop_table(&logger);
        logger.create_table();

        let mut tcp_entry = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
            LogLevel::Db,
        );
        let mut icmpv6_entry = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::ACCEPT,
            LogLevel::Db,
        );
        let mut arp_entry = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
            LogLevel::Db,
        );

        logger.log_entry(tcp_entry.clone());
        logger.log_entry(icmpv6_entry.clone());
        logger.log_entry(arp_entry.clone());

        assert_eq!(logger.console_entries, 0);
        let packets = retrieve_all_packets(&logger);
        // skip equality checks on log level as entries on the DB don't have this info...
        tcp_entry.log_level = LogLevel::All;
        icmpv6_entry.log_level = LogLevel::All;
        arp_entry.log_level = LogLevel::All;
        assert_eq!(packets.len(), 3);
        assert_eq!(*packets.get(0).unwrap(), tcp_entry);
        assert_eq!(*packets.get(1).unwrap(), icmpv6_entry);
        assert_eq!(*packets.get(2).unwrap(), arp_entry);
    }

    #[test]
    #[serial(database_test)]
    fn test_logger_with_log_level_console() {
        let mut logger = Logger {
            db: Connection::open(SQLITE_PATH).unwrap(),
            batch: Vec::new(),
            batch_size: 1,
            console_entries: 0,
        };

        drop_table(&logger);
        logger.create_table();

        let tcp_entry = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
            LogLevel::Console,
        );
        let icmpv6_entry = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::ACCEPT,
            LogLevel::Console,
        );
        let arp_entry = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
            LogLevel::Console,
        );

        logger.log_entry(tcp_entry.clone());
        logger.log_entry(icmpv6_entry.clone());
        logger.log_entry(arp_entry.clone());

        assert_eq!(logger.console_entries, 3);
        let packets = retrieve_all_packets(&logger);
        assert_eq!(packets.len(), 0);
    }

    #[test]
    #[serial(database_test)]
    #[should_panic]
    fn test_logger_with_log_level_off() {
        let mut logger = Logger {
            db: Connection::open(SQLITE_PATH).unwrap(),
            batch: Vec::new(),
            batch_size: 20,
            console_entries: 0,
        };

        drop_table(&logger);
        logger.create_table();

        let tcp_entry = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
            LogLevel::Off,
        );
        let icmpv6_entry = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::ACCEPT,
            LogLevel::Off,
        );
        let arp_entry = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
            LogLevel::Off,
        );

        logger.log_entry(tcp_entry.clone());
        logger.log_entry(icmpv6_entry.clone());
        logger.log_entry(arp_entry.clone());

        assert_eq!(logger.console_entries, 0);
        let packets = retrieve_all_packets(&logger);
        assert_eq!(packets.len(), 0);
    }

    #[test]
    #[serial(database_test)]
    fn test_logger_correctly_stores_batches_to_db() {
        let mut logger = Logger {
            db: Connection::open(SQLITE_PATH).unwrap(),
            batch: Vec::new(),
            batch_size: 5,
            console_entries: 0,
        };

        drop_table(&logger);
        logger.create_table();

        let tcp_entry = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
            LogLevel::All,
        );
        let icmpv6_entry = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::ACCEPT,
            LogLevel::All,
        );
        let arp_entry = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
            LogLevel::All,
        );

        logger.log_entry(tcp_entry.clone());
        logger.log_entry(tcp_entry.clone());
        logger.log_entry(icmpv6_entry.clone());
        logger.log_entry(arp_entry.clone());

        let mut packets = retrieve_all_packets(&logger);

        // 4 packets have been added but batch size is 5 => table is still empty!
        assert!(packets.is_empty());

        // add a fifth packet
        logger.log_entry(icmpv6_entry.clone());
        packets = retrieve_all_packets(&logger);

        // now the table contains 5 packets
        assert_eq!(packets.len(), 5);
        assert_eq!(*packets.get(0).unwrap(), tcp_entry);
        assert_eq!(*packets.get(1).unwrap(), tcp_entry);
        assert_eq!(*packets.get(2).unwrap(), icmpv6_entry);
        assert_eq!(*packets.get(3).unwrap(), arp_entry);
        assert_eq!(*packets.get(4).unwrap(), icmpv6_entry);

        // add 4 more packets
        logger.log_entry(icmpv6_entry.clone());
        logger.log_entry(arp_entry.clone());
        logger.log_entry(arp_entry.clone());
        logger.log_entry(tcp_entry.clone());
        packets = retrieve_all_packets(&logger);

        // the table still contains 5 packets
        assert_eq!(packets.len(), 5);

        // add a tenth packet
        logger.log_entry(icmpv6_entry.clone());
        packets = retrieve_all_packets(&logger);

        // the table now contains 10 packets
        assert_eq!(packets.len(), 10);
        assert_eq!(*packets.get(0).unwrap(), tcp_entry);
        assert_eq!(*packets.get(1).unwrap(), tcp_entry);
        assert_eq!(*packets.get(2).unwrap(), icmpv6_entry);
        assert_eq!(*packets.get(3).unwrap(), arp_entry);
        assert_eq!(*packets.get(4).unwrap(), icmpv6_entry);
        assert_eq!(*packets.get(5).unwrap(), icmpv6_entry);
        assert_eq!(*packets.get(6).unwrap(), arp_entry);
        assert_eq!(*packets.get(7).unwrap(), arp_entry);
        assert_eq!(*packets.get(8).unwrap(), tcp_entry);
        assert_eq!(*packets.get(9).unwrap(), icmpv6_entry);
    }
}
