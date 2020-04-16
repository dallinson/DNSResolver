from sys import exit


def is_pointer(hex_input, start_offset):
    """Determines if the length octet at a position is a pointer or not.
    Args:
        hex_input (str): The hex string used to create the dns response.
        start_offset (int): The position in the hex string that the length octet starts at.

    Returns:
        tuple (bool, int): The boolean in the tuple indicates whether the octet is a pointer-True if it is, False otherwise.
            The int is the start position of the address pointed to if it is a pointer or the value of the length octet otherwise.

    """
    name_count = int(hex_input[start_offset:start_offset + 4], 16)
    is_pointer = (name_count >= 49152)
    # As the count is an int converted from a boolean if it is larger than
    # 49152 the first two bits are 11 so it is a pointer.
    if is_pointer:
        return (True, name_count - 49152)
        # This removed the first two bits by subtracting 49152
    else:
        return (False, int(hex_input[start_offset:start_offset + 2], 16))


def get_qname(hex_input, start_offset):
    """Generates a list containing the domains in a url.
    Args:
        hex_input (str): The hex string used to create the dns response.
        start_offset (int): The position in the hex string that the first length octet of the name starts at.

    Returns:
        list: A list containing the elements in a url
    """
    qname = []
    name_count = int(hex_input[start_offset:start_offset + 2], 16)
    curr_end = start_offset + 2
    while name_count != 0:
        # name_count is 0 when the length octet is 0, i.e. the string 
        # has ended.  Therefore this loops until the end of the name string.
        try:
            if not is_pointer(hex_input, curr_end - 2)[0]:
                pass
            else:
                for elem in get_qname(hex_input, 
                                      is_pointer(hex_input, 
                                                 curr_end - 2)[1] * 2)[1]:
                    qname.append(elem)
                return (curr_end + 2, qname)
            qname.append(bytes.fromhex(
                hex_input[curr_end:curr_end + (name_count * 2)]).decode("utf-8"))
            curr_end = curr_end + 2 + (name_count * 2)
            name_count = int(hex_input[curr_end - 2:curr_end], 16)
        except BaseException:
            print(qname)
            print(curr_end)
            print(hex_input[curr_end])
            test_var = curr_end
            for i in range(10):
                print(bytes.fromhex(
                    hex_input[test_var:test_var + 2]).decode("utf-8"), end="")
                curr_end += 2
            raise
    return (curr_end, qname)


dns_type_dict = {
    1: "A",
    28: "AAAA",
    18: "AFSDB",
    42: "APL",
    257: "CAA",

    60: "CDNSKEY",
    59: "CDS",
    37: "CERT",
    5: "CNAME",
    62: "CSYNC",

    49: "DHCID",
    32769: "DLV",
    39: "DNAME",
    48: "DNSKEY",
    43: "DS",

    13: "HINFO",
    55: "HIP",
    45: "IPSECKEY",
    25: "KEY",
    36: "KX",

    29: "LOC",
    15: "MX",
    35: "NAPTR",
    2: "NS",
    47: "NSEC",

    50: "NSEC3",
    51: "NSEC3PARAM",
    61: "OPENPGPKEY",
    12: "PTR",
    46: "RRSIG",

    17: "RP",
    24: "SIG",
    53: "SMIMEA",
    6: "SOA",
    33: "SRV",

    44: "SSHFP",
    32768: "TA",
    249: "TKEY",
    52: "TLSA",
    250: "TSIG",

    16: "TXT",
    256: "URI",
    63: "ZONEMD",

    # pseudo resource records

    255: "*",
    252: "AXFR",
    251: "IXFR",
    41: "OPT"
}


class QueryRecord:

    def __init__(self, hex_input, start_point):
        self._start_point = start_point
        qname_info = get_qname(hex_input, start_point)
        self._name = qname_info[1]
        self._end_point = qname_info[0]
        self._dns_type = int(
            hex_input[self._end_point:self._end_point + 4], 16)
        self._dns_class = int(
            hex_input[self._end_point + 4:self._end_point + 8], 16)
        self._end_point += 8

    def get_end_point(self):
        return self._end_point

    def get_dns_type(self):
        return (self._dns_type, dns_type_dict[self._dns_type])


class AnswerRecord:

    def __init__(self, hex_input, start_point, dns_response):
        self._start_point = start_point
        qname_info = get_qname(hex_input, start_point)
        self._name = qname_info[1]
        self._end_point = qname_info[0]
        self._dns_type = int(
            hex_input[self._end_point:self._end_point + 4], 16)
        self._dns_class = int(
            hex_input[self._end_point + 4:self._end_point + 8], 16)
        self._ttl = int(hex_input[self._end_point +
                                  8:self._end_point + 16], 16)
        self._rdlength = int(
            hex_input[self._end_point + 16:self._end_point + 20], 16)
        self._rdata = hex_input[self._end_point +
                                20:self._end_point + 20 + (self._rdlength * 2)]
        self._end_point += 20 + (self._rdlength * 2)
        self._response = dns_response
        if dns_type_dict[self._dns_class] == "OPT":
            print("OPT")

    def get_end_point(self):
        return self._end_point

    def get_dns_type(self):
        return (self._dns_type, dns_type_dict[self._dns_type])

    def get_rdata(self):
        if dns_type_dict[self._dns_type] == 'CNAME' or dns_type_dict[self._dns_type] == 'NS':
            return get_qname(
                self._response.get_hex(),
                self._response.get_hex().find(
                    self._rdata))[1]
        elif dns_type_dict[self._dns_type] == 'A':
            octet_list = []
            for i in range(4):
                octet_list.append(str(int(self._rdata[i * 2:(i * 2) + 2], 16)))
            return ".".join(octet_list)

    def get_name(self):
        return self._name


class DNSResponse:
    def __init__(self, hex_input):
        self._id = hex_input[0:4]
        response_data = str(bin(int(hex_input[4:8], 16)))[2:]
        self._qr = True if response_data[0] == '1' else False
        self._opcode = int(response_data[1:5], 2)
        self._aa = True if response_data[5] == '1' else False
        self._tc = True if response_data[6] == '1' else False
        self._rd = True if response_data[7] == '1' else False
        self._ra = True if response_data[8] == '1' else False
        self._z = int(response_data[9:12], 2)
        self._rcode = int(response_data[12:], 2)
        if self._z != 0:
            print("Z section of DNS header is not 0, exiting")
            exit(0)
        elif self._rcode != 0:
            if self._rcode == 1:
                print("The server was unable to interpret the query. (Error code 1)")
                exit(1)
            elif self._rcode == 2:
                print("An error occured in the name server so the query could not be processed. (Error code 2)")
                exit(0)
            elif self._rcode == 3:
                print("The requested URL does not exist. (Error code 3)")
                exit(0)
            elif self._rcode == 4:
                print("The name server does not support this type of query. (Error code 4)")
                exit(1)
            elif self._rcode == 5:
                print("The name server has refused to execute this query due to its policy. (Error code 5)")
                exit(1)
            else:
                print("Something went wrong!")
                exit(1)
        elif self._tc:
            print("The DNS response was truncated, this resolver does not support truncated responses.")
            exit(1)
        self._qdcount = int(hex_input[8:12], 16)
        self._ancount = int(hex_input[12:16], 16)
        self._nscount = int(hex_input[16:20], 16)
        self._arcount = int(hex_input[20:24], 16)
        pointer = 24
        self._qdrecords = []
        self._anrecords = []
        self._nsrecords = []
        self._arrecords = []
        for i in range(self._qdcount):
            self._qdrecords.append(QueryRecord(hex_input, pointer))
            pointer = self._qdrecords[-1].get_end_point()
        for i in range(self._ancount):
            self._anrecords.append(AnswerRecord(hex_input, pointer, self))
            pointer = self._anrecords[-1].get_end_point()
        for i in range(self._nscount):
            self._nsrecords.append(AnswerRecord(hex_input, pointer, self))
            pointer = self._nsrecords[-1].get_end_point()
        for i in range(self._arcount):
            self._arrecords.append(AnswerRecord(hex_input, pointer, self))
            pointer = self._arrecords[-1].get_end_point()
        self._hex = hex_input

    def get_query_records(self):
        return self._qdrecords

    def get_answer_records(self):
        return self._anrecords

    def get_nameserver_records(self):
        return self._nsrecords

    def get_additional_records(self):
        return self._arrecords

    def get_record_counts(self):
        return (self._qdcount, self._ancount, self._nscount, self._arcount)

    def get_hex(self):
        return self._hex

    def is_authoritative_answer(self):
        return self._aa
