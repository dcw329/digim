import dns
import dns.name
import dns.query
import dns.resolver
import click
import whois
import dns.zone
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *
import socket
 

GOOGLE = ['google-public-dns-a.google.com', 'google-public-dns-a.google.com']
LEVEL3 = ['a.resolvers.level3.net', 'b.resolvers.level3.net', 'c.resolvers.level3.net']
IMH = ['ns.inmotionhosting.com', 'ns2.inmotionhosting.com']
WHH = ['ns1.webhostinghub.com', 'ns2.webhostinghub.com']

                
provider_list = ['level3', 'google', 'inmotionhosting', 'webhostinghub']
master_list = ['google-public-dns-a.google.com', 'google-public-dns-a.google.com','a.resolvers.level3.net', 'b.resolvers.level3.net', 'c.resolvers.level3.net','ns.inmotionhosting.com', 'ns2.inmotionhosting.com', 'ns1.webhostinghub.com', 'ns2.webhostinghub.com']



lineoptions = {"nlines": 10, "width": 100, "ptr": None}



def pull_record(domain, record_type, nameserver):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = list(str(nameserver)) 
    try:
        answers = resolver.query(domain, record_type.upper())
    except (dns.resolver.NoAnswer):
        try:
            answers = dns.query.udp(domain, nameserver)
        except (dns.resolver.NoAnswer):
            raise dns.resolver.NoAnswer
    for answer in answers:
        print 'Host', answer


def get_records(domain):
    pull_record(domain, "A", '8.8.8.8')
    pull_record(domain, "CNAME", '8.8.8.8')
    pull_record(domain, "MX", '8.8.8.8')
    pull_record(domain, "NS", '8.8.8.8')


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

def rdns_for_dns(hostname):
    ip = None
    if is_valid_ipv4_address(hostname):
        ip = hostname
        return ip
    if is_valid_ipv6_address(hostname):
        ip = hostname
        return ip
    try:
        ip = socket.gethostbyname(hostname)
    except:
        pass
    
    return ip

# def update_ns_list():
#     master_ns_list = ['dns.google.com', 'ns.inmotionhosting.com', 'a.resolvers.level3.net', '8.8.8.8']
#     ns_to_ips = []
#     for prvdr in master_ns_list:
#         ns_to_ips.append(rdns_for_dns(prvdr))
        
#     return ns_to_ips
        
        

# def get_google_dns(domain)
#     print "@google-public-dns-a: %s [ PTR: %s ] " \
#         % pullrecord(domain, "A", 8.8.8.8) \ 
#         pullrecord(domain, "PTR", 8.8.8.8)
#     print "@google-public-dns-b: %s [ PTR: %s ] " \
#         % pullrecord(domain, "A", 8.8.4.4) \ 
#         pullrecord(domain, "PTR", 8.8.4.4)


def header(text):
    """Prints a pretty lil header"""
    o = lineoptions
    hlen = len(text)
    hline = "".join("-" for i in xrange(o["width"] - hlen - 2)) 
    return "\n%s-%s" % (text, hline)


def currentwhois(domain):
    who = whois.query(domain)
    print "Domain Name %s" % who.name
    print "Registrar   %s" % who.registrar
    print "Expiration  %s" % who.expiration_date
    print "Registrar   %s" % who.registrar
    for ns in who.name_servers:
        print "NameServer  %s" % ns
    # print(who.__dict__)

    print '{0:15} ==> {1:20}'.format('Domain Name', who.name)



def zonerecords(domain):
    answers = dns.resolver.query(domain, 'SOA')
    print 'query qname:', answers.qname, ' num ans.', len(answers)
    for rdata in answers:
        print ' serial: %s  tech: %s' % (rdata.serial, rdata.rname)
        print ' refresh: %s  retry: %s' % (rdata.refresh, rdata.retry)
        print ' expire: %s  minimum: %s' % (rdata.expire, rdata.minimum)
        print ' mname: %s' % (rdata.mname)
    
    zone = dns.resolver.query(domain)
    for record in zone:
        print record


def pull_serial(domain, nameserver):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = list(str(nameserver))
    answer = dns.resolver.query(domain, 'SOA')
    return answer.serial


def get_a_records(domain):
    for provider in provider_list:
        print "%s's Public DNS:" % provider
# ['print/output' item 'while running through a for loop for' for item in master_list 'and if statement is true due to' if provider in item 'go back to the beginning']
        for nameserver in [item.lower() for item in master_list if provider.lower() in item.lower()]:
            print "%s: %s [ PTR: %s ] " % (
                                        nameserver,        
                                        pull_record(domain, "A", rdns_for_dns(nameserver)), 
                                        pull_record(domain, "PTR", rdns_for_dns(nameserver))
                                        )
            print "     > Serial: %s " % pull_serial(domain, rdns_for_dns(nameserver))

        

#@click.command()
#@click.option('-d', '--domain', type=str )
def digim(domain):
    domain = str('dcwtest.com')
    print header("hello world")
    print get_a_records(domain)
#    print currentwhois(domain)
    print zonerecords(domain)

#    print getrecords(domain)


if __name__ == '__main__':
    digim('dcwtest.com')




