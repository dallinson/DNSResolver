import socket
import records
import binascii

def url_to_list(url):
    return url.split(".")


def make_query_string(url_list):
    for i in range(len(url_list)):
        hex_str = str(binascii.hexlify(url_list[i].encode("utf-8")))[2:-1]
        url_list[i] = ("{:02x}".format(int(len(hex_str) / 2))) + hex_str
    return "".join(url_list) + "00"


def get_ip_for_ns(ns_record, a_records):
    if ns_record.get_dns_type()[1] != "NS":
        return None
    for record in a_records:
        if record.get_dns_type()[1] == "A":
            return record.get_rdata()
    return query(
        '198.41.0.4',
        '133701000001000000000000' +
        make_query_string(
            ns_record.get_rdata()) +
        '00010001')


def query(ip, query_string):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, 53))

    sock.send(bytes.fromhex(query_string))

    test = sock.recv(512)
    sock.close()

    dnsResponse = records.DNSResponse(test.hex())

    if (not dnsResponse.is_authoritative_answer()) and (
            dnsResponse.get_record_counts()[1] == 0):
        return query(
            get_ip_for_ns(
                dnsResponse.get_nameserver_records()[0],
                dnsResponse.get_additional_records()),
            query_string)
    else:
        if dnsResponse.get_answer_records()[0].get_dns_type()[1] == "CNAME":
            return query(
                '198.41.0.4',
                '133701000001000000000000' +
                make_query_string(
                    dnsResponse.get_answer_records()[0].get_rdata()) +
                '00010001')
        else:
            return dnsResponse.get_answer_records()[0].get_rdata()


print(
    query(
        '198.41.0.4',
        '133701000001000000000000' +
        make_query_string(
            url_to_list(
                input("Enter URL here: "))) +
        '00010001'))
