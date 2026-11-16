// Asks Windows' own DNS client. This is the only place in the DNS Lookup that calls Windows,
// and the only place with unsafe code.
//
// Going through the Windows DNS client means the answer comes from the DNS settings this PC
// already uses, including a VPN's or a workplace's DNS and any rules for particular domains,
// exactly as it would for a browser. Tenax does not choose a DNS server and does not contact
// any public one.
//
// The unsafe parts are small and each has one job:
//   query()   calls Windows and walks the list of records it returns
//   record()  reads one record out of that list
//   text()    reads a C string
// The list is released by RecordList when it goes out of scope, even if something panics.

use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::slice;

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::Dns::{
    DNS_QUERY_NO_HOSTS_FILE, DNS_QUERY_NO_MULTICAST, DNS_QUERY_NO_NETBT, DNS_QUERY_OPTIONS,
    DNS_QUERY_TREAT_AS_FQDN, DNS_RECORDA, DNS_TYPE, DnsFree, DnsFreeRecordList, DnsQuery_A,
};
use windows::core::{PCSTR, PSTR};

use super::records::{Answer, Data, Failure, Kind, Record, Resolver};

// What to ask Windows for:
//   treat the name as complete, so a work network's search suffixes are not added to it
//   do not use NetBIOS or multicast, which would announce the name to the local network
//   do not use the hosts file, so what is shown is what DNS says
// The DNS cache is still used, as it is for everything else on this PC.
const OPTIONS: DNS_QUERY_OPTIONS = DNS_QUERY_OPTIONS(
    DNS_QUERY_TREAT_AS_FQDN.0
        | DNS_QUERY_NO_NETBT.0
        | DNS_QUERY_NO_MULTICAST.0
        | DNS_QUERY_NO_HOSTS_FILE.0,
);

// The record type numbers DNS uses.
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;

// Windows' own error numbers for the answers that are not a failure of the lookup.
const NO_SUCH_DOMAIN: u32 = 9003;
const NO_RECORDS: [u32; 2] = [9501, 9701];
const SERVER_FAILED: u32 = 9002;
const REFUSED: u32 = 9005;
const TIMEOUT: u32 = 1460;
const NO_SERVERS: u32 = 9852;

// The most pieces one text record is read from. Real ones have a handful.
const MAX_TEXT_PIECES: usize = 256;

pub struct WindowsDns;

fn type_of(kind: Kind) -> u16 {
    match kind {
        Kind::A => TYPE_A,
        Kind::Aaaa => TYPE_AAAA,
        Kind::Mx => TYPE_MX,
        Kind::Ns => TYPE_NS,
        Kind::Txt => TYPE_TXT,
        Kind::Soa => TYPE_SOA,
    }
}

fn failure(code: u32) -> Failure {
    match code {
        NO_SUCH_DOMAIN => Failure::NoSuchDomain,
        code if NO_RECORDS.contains(&code) => Failure::NoRecords,
        SERVER_FAILED => Failure::ServerFailed,
        REFUSED => Failure::Refused,
        TIMEOUT => Failure::Timeout,
        NO_SERVERS => Failure::NoServers,
        other => Failure::Other(other),
    }
}

// Releases the records Windows returned.
struct RecordList(*mut DNS_RECORDA);

impl Drop for RecordList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the list came from DnsQuery_A, which says to free it with DnsFreeRecordList,
            // and it is freed only here, once.
            unsafe { DnsFree(Some(self.0 as *const c_void), DnsFreeRecordList) };
        }
    }
}

// SAFETY: the pointer is either null or a C string that Windows keeps alive until the list is freed.
unsafe fn text(pointer: PSTR) -> String {
    if pointer.0.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(pointer.0 as *const c_char) }
        .to_string_lossy()
        .into_owned()
}

// Whether a record is part of the answer, rather than extra information the server added.
fn is_answer(record: &DNS_RECORDA) -> bool {
    // The lowest two bits of the flags say which section the record came from. 1 is the answer.
    // SAFETY: both members of the union are plain integers.
    (unsafe { record.Flags.DW } & 0b11) == 1
}

// Reads one record. A kind of record that Tenax does not use gives None.
// SAFETY: `record` must be a record that Windows returned, whose strings are still alive.
unsafe fn record(record: &DNS_RECORDA) -> Option<Record> {
    let data = unsafe {
        match record.wType {
            TYPE_A => Data::A(Ipv4Addr::from(record.Data.A.IpAddress.to_ne_bytes())),
            TYPE_AAAA => Data::Aaaa(Ipv6Addr::from(record.Data.AAAA.Ip6Address.IP6Byte)),
            TYPE_MX => Data::Mx {
                preference: record.Data.MX.wPreference,
                host: text(record.Data.MX.pNameExchange),
            },
            TYPE_NS => Data::Ns(text(record.Data.NS.pNameHost)),
            TYPE_CNAME => Data::Cname(text(record.Data.CNAME.pNameHost)),
            TYPE_SOA => Data::Soa {
                primary: text(record.Data.SOA.pNamePrimaryServer),
                admin: text(record.Data.SOA.pNameAdministrator),
                serial: record.Data.SOA.dwSerialNo,
            },
            TYPE_TXT => {
                // The pieces are a list that starts inside the record and runs on past it.
                let txt = &record.Data.TXT;
                let count = (txt.dwStringCount as usize).min(MAX_TEXT_PIECES);
                let pieces = slice::from_raw_parts(txt.pStringArray.as_ptr(), count);
                Data::Txt(pieces.iter().map(|piece| text(*piece)).collect())
            }
            _ => return None,
        }
    };

    Some(Record {
        name: unsafe { text(record.pName) },
        ttl: record.dwTtl,
        data,
    })
}

// Whether a record answers the question. Asking for an address also returns the aliases on
// the way to it, and those are kept.
fn answers(kind: Kind, data: &Data) -> bool {
    matches!(
        (kind, data),
        (Kind::A, Data::A(_) | Data::Cname(_))
            | (Kind::Aaaa, Data::Aaaa(_) | Data::Cname(_))
            | (Kind::Mx, Data::Mx { .. })
            | (Kind::Ns, Data::Ns(_))
            | (Kind::Txt, Data::Txt(_))
            | (Kind::Soa, Data::Soa { .. })
    )
}

impl Resolver for WindowsDns {
    fn query(&self, name: &str, kind: Kind) -> Answer {
        let name = CString::new(name).map_err(|_| Failure::Other(123))?;
        let mut found: *mut DNS_RECORDA = std::ptr::null_mut();

        // SAFETY: `name` is a valid C string that outlives the call, and `found` is a place for
        // Windows to put the pointer to the list it builds.
        let status: WIN32_ERROR = unsafe {
            DnsQuery_A(
                PCSTR(name.as_ptr() as *const u8),
                DNS_TYPE(type_of(kind)),
                OPTIONS,
                None,
                &mut found,
                None,
            )
        };
        // From here the list is released when `list` goes out of scope.
        let list = RecordList(found);
        if status.0 != 0 {
            return Err(failure(status.0));
        }

        let mut records = Vec::new();
        let mut current = list.0 as *const DNS_RECORDA;
        while !current.is_null() {
            // SAFETY: each pointer in the list is valid until the list is freed.
            let raw = unsafe { &*current };
            if is_answer(raw)
                && let Some(parsed) = unsafe { record(raw) }
                && answers(kind, &parsed.data)
            {
                records.push(parsed);
            }
            current = raw.pNext;
        }

        if records.is_empty() {
            Err(Failure::NoRecords)
        } else {
            Ok(records)
        }
    }
}

// =========================
// Tests
// =========================

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use windows::Win32::NetworkManagement::Dns::{
        DNS_MX_DATAA, DNS_PTR_DATAA, DNS_RECORDA_0, DNS_SOA_DATAA,
    };

    use super::*;

    // A string that lives for the test, as Windows' would while the list is alive.
    fn c(text: &str) -> (CString, PSTR) {
        let owned = CString::new(text).unwrap();
        let pointer = PSTR(owned.as_ptr() as *mut u8);
        (owned, pointer)
    }

    fn blank(kind: u16) -> DNS_RECORDA {
        DNS_RECORDA {
            wType: kind,
            dwTtl: 300,
            // The lowest two bits say the record is in the answer section.
            Flags: DNS_RECORDA_0 { DW: 1 },
            ..Default::default()
        }
    }

    #[test]
    fn address_records_are_read_from_their_bytes() {
        let (_name, name) = c("example.com");
        let mut a = blank(TYPE_A);
        a.pName = name;
        a.Data.A.IpAddress = u32::from_ne_bytes([93, 184, 216, 34]);
        let read = unsafe { record(&a) }.unwrap();
        assert_eq!(read.name, "example.com");
        assert_eq!(read.ttl, 300);
        assert_eq!(read.data, Data::A(Ipv4Addr::new(93, 184, 216, 34)));

        let mut aaaa = blank(TYPE_AAAA);
        aaaa.Data.AAAA.Ip6Address.IP6Byte = Ipv6Addr::LOCALHOST.octets();
        assert_eq!(
            unsafe { record(&aaaa) }.unwrap().data,
            Data::Aaaa(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn names_and_mail_records_are_read() {
        let (_host, host) = c("mail.example.com");
        let mut mx = blank(TYPE_MX);
        mx.Data.MX = DNS_MX_DATAA {
            pNameExchange: host,
            wPreference: 10,
            Pad: 0,
        };
        assert_eq!(
            unsafe { record(&mx) }.unwrap().data,
            Data::Mx {
                preference: 10,
                host: "mail.example.com".to_string()
            }
        );

        let (_ns, ns_name) = c("ns1.example.com");
        let mut ns = blank(TYPE_NS);
        ns.Data.NS = DNS_PTR_DATAA { pNameHost: ns_name };
        assert_eq!(
            unsafe { record(&ns) }.unwrap().data,
            Data::Ns("ns1.example.com".to_string())
        );

        let (_target, target) = c("target.example.net");
        let mut cname = blank(TYPE_CNAME);
        cname.Data.CNAME = DNS_PTR_DATAA { pNameHost: target };
        assert_eq!(
            unsafe { record(&cname) }.unwrap().data,
            Data::Cname("target.example.net".to_string())
        );
    }

    #[test]
    fn a_start_of_authority_record_is_read() {
        let (_primary, primary) = c("ns1.example.com");
        let (_admin, admin) = c("hostmaster.example.com");
        let mut soa = blank(TYPE_SOA);
        soa.Data.SOA = DNS_SOA_DATAA {
            pNamePrimaryServer: primary,
            pNameAdministrator: admin,
            dwSerialNo: 2030010101,
            dwRefresh: 0,
            dwRetry: 0,
            dwExpire: 0,
            dwDefaultTtl: 0,
        };
        assert_eq!(
            unsafe { record(&soa) }.unwrap().data,
            Data::Soa {
                primary: "ns1.example.com".to_string(),
                admin: "hostmaster.example.com".to_string(),
                serial: 2030010101
            }
        );
    }

    #[test]
    fn a_text_record_in_several_pieces_is_joined() {
        // In Windows' layout the text pieces are an array of pointers that starts in the record's
        // data and runs on through the rest of that data area. The test builds the same thing by
        // writing the later pointers into the space after the first one.
        let (_a, first) = c("v=spf1 include:_spf.example.com ");
        let (_b, second) = c("-all");
        let (_c, third) = c("");

        let mut raw = blank(TYPE_TXT);
        // SAFETY: the record is built as a text record, and the data area of the record is far
        // larger than the three pointers written into it.
        unsafe {
            raw.Data.TXT.dwStringCount = 3;
            let pieces = raw.Data.TXT.pStringArray.as_mut_ptr();
            pieces.write(first);
            pieces.add(1).write(second);
            pieces.add(2).write(third);
        }

        let read = unsafe { record(&raw) }.unwrap();
        assert_eq!(
            read.data,
            Data::Txt("v=spf1 include:_spf.example.com -all".to_string())
        );
    }

    #[test]
    fn an_absurd_piece_count_is_capped_and_unknown_types_are_skipped() {
        // A record type Tenax does not use is ignored.
        assert!(unsafe { record(&blank(99)) }.is_none());
        // Only records in the answer section count.
        let mut extra = blank(TYPE_A);
        extra.Flags.DW = 2;
        assert!(!is_answer(&extra));
        assert!(is_answer(&blank(TYPE_A)));
    }

    #[test]
    fn windows_error_numbers_become_the_right_failures() {
        assert_eq!(failure(9003), Failure::NoSuchDomain);
        assert_eq!(failure(9501), Failure::NoRecords);
        assert_eq!(failure(9701), Failure::NoRecords);
        assert_eq!(failure(9002), Failure::ServerFailed);
        assert_eq!(failure(9005), Failure::Refused);
        assert_eq!(failure(1460), Failure::Timeout);
        assert_eq!(failure(9852), Failure::NoServers);
        assert_eq!(failure(1234), Failure::Other(1234));
        assert!(Failure::Timeout.is_unreachable() && !Failure::NoSuchDomain.is_unreachable());
    }

    #[test]
    fn an_alias_in_the_answer_is_kept_when_asking_for_an_address() {
        let alias = Data::Cname("a.example.net".to_string());
        assert!(answers(Kind::A, &alias) && answers(Kind::Aaaa, &alias));
        assert!(!answers(Kind::Mx, &alias));
        assert!(!answers(Kind::Txt, &Data::A(Ipv4Addr::LOCALHOST)));
    }

    // Asks this PC's real DNS about a domain that exists for this purpose. It sends the name
    // to the DNS server this PC uses, so it only runs when asked for:
    //   cargo test -- --ignored --nocapture asks_windows_dns
    #[test]
    #[ignore]
    fn asks_windows_dns() {
        for kind in [
            Kind::A,
            Kind::Aaaa,
            Kind::Mx,
            Kind::Ns,
            Kind::Txt,
            Kind::Soa,
        ] {
            let answer = WindowsDns.query("example.com", kind);
            println!("{kind:?}: {answer:?}");
        }
        // The ending .invalid is reserved so that it can never exist, which makes it a safe way to
        // see a "no such domain" answer.
        let missing = WindowsDns.query("tenax-no-such-name.invalid", Kind::A);
        println!("missing: {missing:?}");
        assert!(WindowsDns.query("example.com", Kind::A).is_ok());
        assert_eq!(missing, Err(Failure::NoSuchDomain));
    }
}
