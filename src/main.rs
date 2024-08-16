use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub struct BytePacketBuffer {
    /// Buffer for holding the packet contents
    pub buf: [u8;512],
    /// Field for keeping track of where we are
    pub pos: usize,
}

impl BytePacketBuffer {
    /// Constructor for the BytePacketBuffer
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0;512],
            pos: 0,
        }
    }

    /// get Current position within buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    /// Read a single byte and move the position one step forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of the buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    /// Get a single byte, without chaning the buffer position
    fn get(&mut self, pos: usize) -> Result<u8> {
        if  pos >= 512 {
            return Err("End of the buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of the buffer".into());
        }
        Ok(&self.buf[start..start+len as usize])
    }

    /// Read two bytes, stepping two steps forward
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24) | ((self.read()? as u32) << 16) | ((self.read()? as u32) << 8) | (self.read()? as u32);
        Ok(res)
    }

    /// Read a qname
    ///
    /// A qname is a series of labels, where each label consists of a length byte followed by the actual string.
    /// The qname is terminated by a zero-length label.
    /// Reading domain names, taking labels into consideration
    /// will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to the outstr
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

         // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // DNS packets are unstructured data, so we need to be paranoid. Someone can craft a packet with a cycle in the jump instructions, causing us to loop forever. To prevent this, we'll limit the number of jumps we can perform.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // At this point, we're always at the beginning of a label. The first byte of a label is its length, so we can read that first.
            let len = self.get(pos)?;

            // If len has the two most significant bits set, it means that this is a pointer to somewhere else in the packet. We'll read the next byte and combine the two to get the actual position.
            
            // If len has the two most significant bit are set, it represents a jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and jump to that position and update the position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }else{
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0. If we encounter that, we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to the output buffer first
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them to the output buffer
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());
                delim = ".";

                // Move forward the full length of the label
                pos += len as usize;
            }
        }
        if !jumped {
            self.seek(pos)?;
        }
        Ok(())
    }

    /// Write the buffer
    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("End of the buffer".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }


}

/// Result Code Enum
/// This enum represents the possible result codes that can be returned in a DNS response.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

/// DNS Header
/// The header of a DNS packet is always 12 bytes long and contains the following fields:
/// 1. Transaction ID: A 16-bit identifier assigned by the program that generates any kind of query. This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
/// 2. Flags: A 16-bit field broken into a few different parts:
///     - QR (1 bit): This is the query/response flag. 0 means this message is a query, 1 means it is a response.
///     - OPCODE (4 bits): This is the kind of query in the message. 0 is a standard query, 1 is an inverse query, 2 is a server status request, and 3-15 are reserved for future use.
///     - AA (1 bit): This is the Authoritative Answer bit. It says something about whether the DNS server responding to the query is authoritative for the domain name in question.
///     - TC (1 bit): This is the TrunCation bit. It says something about whether the message was truncated.
///     - RD (1 bit): This is the Recursion Desired bit. It says something about whether the client that sent the query wants the DNS server to recurse when it doesn't have the answer.
///     - RA (1 bit): This is the Recursion Available bit. It says something about whether the DNS server that sent the response supports recursion.
///     - Z (3 bits): Reserved for future use. Must be zero in all queries and responses.
///     - RCODE (4 bits): This is the Response CODE. It says something about whether the query was successful or not.
/// 3. QDCOUNT: A 16-bit field specifying the number of entries in the question section.
/// 4. ANCOUNT: A 16-bit field specifying the number of resource records in the answer section.
/// 5. NSCOUNT: A 16-bit field specifying the number of name server resource records in the authority records section.
/// 6. ARCOUNT: A 16-bit field specifying the number of resource records in the additional records section.
#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, //16 bits  | Transaction ID

    pub recursion_desired: bool, // 1 bit | Recursion Desired
    pub truncated_message: bool, // 1 bit | TrunCation
    pub authoritative_answer: bool, // 1 bit | Authoritative Answer
    pub opcode: u8, // 4 bits | OPCODE
    pub response: bool, // 1 bit | QR

    pub rescode: ResultCode, // 4 bits | RCODE
    pub checking_disabled: bool, // 1 bit | Checking Disabled
    pub authed_data: bool, // 1 bit | Authenticated Data
    pub z: bool, // 1 bit | Z
    pub recursion_available: bool, // 1 bit | Recursion Available

    pub questions: u16, // 16 bits | QDCOUNT
    pub answers: u16, // 16 bits | ANCOUNT
    pub authoritative_entries: u16, // 16 bits | NSCOUNT
    pub resource_entries: u16, // 16 bits | ARCOUNT
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    /// Reading the header from the buffer
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {

        // Example for better understanding
        // header = 1a 2b 81 80 00 01 00 01 00 00 00 00
        // id = 0x1a2b | binary = 000110100101011 | decimal = 6699
        // flags = 0x8180 | binary = 1000000110000000 | decimal = 33024
        // a = 0x81 | binary = 10000001 | decimal = 129
        // b = 0x80 | binary = 10000000 | decimal = 128
        // recursion_desired = 0x81 & 0x01 = 1
        // truncated_message = 0x81 & 0x02 = 0
        // authoritative_answer = 0x81 & 0x04 = 0
        // opcode = 0x81 >> 3 = 0x10 = 2
        // response = 0x81 & 0x80 = 1

        // rescode = 0x80 & 0x0F = 0
        // checking_disabled = 0x80 & 0x10 = 0
        // authed_data = 0x80 & 0x20 = 0
        // z = 0x80 & 0x40 = 0
        // recursion_available = 0x80 & 0x80 = 1

        // questions = 0x0001 = 1
        // answers = 0x0001 = 1
        // authoritative_entries = 0x0000 = 0
        // resource_entries = 0x0000 = 0

        self.id = buffer.read_u16()?;
 

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())

        
    }
}

/// Query Type Enum
/// This enum represents the possible query types that can be made in a DNS query.

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

/// DnsQuestion
/// The question section of a DNS packet is used to request information about a specific domain name.
/// It contains the following fields:
/// 1. QNAME: A domain name represented as a series of labels.
/// 2. QTYPE: A 16-bit field specifying the type of the query.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }

    /// Reading the question from the buffer
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class
        Ok(())
    }
}

/// DnsRecord 
/// The answer, authority, and additional sections of a DNS packet all contain resource records.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?; // class
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );
                Ok(DnsRecord::A {
                    domain,
                    addr,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;
                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }
}

/// DnsPacket
/// The DNS packet is the top-level structure that contains the header, question, and resource records.
#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// Reading the packet from the buffer
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        // Reading the questions
        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }
        
        // Reading the answers
        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }

        // Reading the authorities
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        
        // Reading the resources
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }
}

fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}