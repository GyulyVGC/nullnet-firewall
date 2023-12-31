use std::sync::mpsc::Receiver;

use rusqlite::Connection;

use crate::LogEntry;

struct Logger {
    db: Connection,
    batch: Vec<LogEntry>,
    batch_size: usize,
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

    fn add_entry(&mut self, log_entry: LogEntry) {
        self.batch.push(log_entry);
        if self.batch.len() >= self.batch_size {
            // write the batch to the DB in a single transaction
            self.store_batch();
            self.batch = Vec::new();
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
        let log_entry = rx.recv().expect("channel is down");

        // log into console
        println!("{log_entry}");

        // log into db
        logger.add_entry(log_entry);
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use serial_test::serial;

    use crate::logs::logger::{Logger, SQLITE_PATH};
    use crate::utils::raw_packets::test_packets::{ARP_PACKET, ICMPV6_PACKET, TCP_PACKET};
    use crate::{DataLink, Fields, FirewallAction, FirewallDirection, LogEntry};

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
    fn test_logger_correctly_stores_entries_to_db() {
        let mut logger = Logger {
            db: Connection::open(SQLITE_PATH).unwrap(),
            batch: Vec::new(),
            batch_size: 1,
        };

        drop_table(&logger);
        logger.create_table();

        let tcp_entry = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
        );
        let icmpv6_entry = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::ACCEPT,
        );
        let arp_entry = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
        );

        logger.add_entry(tcp_entry.clone());
        logger.add_entry(icmpv6_entry.clone());
        logger.add_entry(arp_entry.clone());

        let packets = retrieve_all_packets(&logger);
        assert_eq!(packets.len(), 3);
        assert_eq!(*packets.get(0).unwrap(), tcp_entry);
        assert_eq!(*packets.get(1).unwrap(), icmpv6_entry);
        assert_eq!(*packets.get(2).unwrap(), arp_entry);
    }

    #[test]
    #[serial(database_test)]
    fn test_logger_correctly_stores_batches_to_db() {
        let mut logger = Logger {
            db: Connection::open(SQLITE_PATH).unwrap(),
            batch: Vec::new(),
            batch_size: 5,
        };

        drop_table(&logger);
        logger.create_table();

        let tcp_entry = LogEntry::new(
            &Fields::new(&TCP_PACKET, DataLink::Ethernet),
            FirewallDirection::IN,
            FirewallAction::DENY,
        );
        let icmpv6_entry = LogEntry::new(
            &Fields::new(&ICMPV6_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::ACCEPT,
        );
        let arp_entry = LogEntry::new(
            &Fields::new(&ARP_PACKET, DataLink::Ethernet),
            FirewallDirection::OUT,
            FirewallAction::REJECT,
        );

        logger.add_entry(tcp_entry.clone());
        logger.add_entry(tcp_entry.clone());
        logger.add_entry(icmpv6_entry.clone());
        logger.add_entry(arp_entry.clone());

        let mut packets = retrieve_all_packets(&logger);

        // 4 packets have been added but batch size is 5 => table is still empty!
        assert!(packets.is_empty());

        // add a fifth packet
        logger.add_entry(icmpv6_entry.clone());
        packets = retrieve_all_packets(&logger);

        // now the table contains 5 packets
        assert_eq!(packets.len(), 5);
        assert_eq!(*packets.get(0).unwrap(), tcp_entry);
        assert_eq!(*packets.get(1).unwrap(), tcp_entry);
        assert_eq!(*packets.get(2).unwrap(), icmpv6_entry);
        assert_eq!(*packets.get(3).unwrap(), arp_entry);
        assert_eq!(*packets.get(4).unwrap(), icmpv6_entry);

        // add 4 more packets
        logger.add_entry(icmpv6_entry.clone());
        logger.add_entry(arp_entry.clone());
        logger.add_entry(arp_entry.clone());
        logger.add_entry(tcp_entry.clone());
        packets = retrieve_all_packets(&logger);

        // the table still contains 5 packets
        assert_eq!(packets.len(), 5);

        // add a tenth packet
        logger.add_entry(icmpv6_entry.clone());
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
