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
 

provider_list = ['level3', 'google', 'inmotionhosting', 'webhostinghub']
dns_list = ['google-public-dns-a.google.com', 'google-public-dns-a.google.com','a.resolvers.level3.net', 'b.resolvers.level3.net', 'c.resolvers.level3.net','ns.inmotionhosting.com', 'ns2.inmotionhosting.com', 'ns1.webhostinghub.com', 'ns2.webhostinghub.com']



lineoptions = {"nlines": 10, "width": 100, "ptr": None}


#returns 1 answer
def pull_record(domain, record_type, nameserver):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ str(nameserver) ]
    try:
        answers = resolver.query(domain, record_type)
    except (dns.resolver.NoAnswer):
        try:
            answers = dns.query.udp(domain, nameserver)
        except (dns.resolver.NoAnswer):
            raise dns.resolver.NoAnswer
    # When there is no record in our nameservers, they
    # return an rcode=REFUSED . This removes the nameserver
    # from the list in resolver.nameservers raising a 
    # return of NoNameserver. Handle this as no record later
    except (dns.resolver.NoNameservers):
        return "REFUSED"
    return answers[0]


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
    return answer[0].serial


def pull_ptr(ip):
    resolver = dns.resolver.Resolver()
    return str(resolver.query(ip,"PTR")[0])


def get_a_records(domain):
    for provider in provider_list:
        print "%s's Public DNS:" % provider
        # ['print/output' item 'while running through a for loop for' 
        # for item in dns_list 'and if statement is true due to' 
        # if provider in item 'go back to the beginning']
        for nameserver in [item.lower() for item in dns_list if provider.lower() in item.lower()]:
            thea = pull_record(domain, "A",  rdns_for_dns(nameserver))
            if thea != "REFUSED":
                thea = str(thea)
                addr = dns.reversename.from_address(thea)
                ptr = pull_ptr(addr)
                serial = pull_serial(domain, rdns_for_dns(nameserver))
            else:
                ptr = thea
                serial = thea
            print "  %s: %s [ PTR: %s ] " % (nameserver, thea, ptr)
            print "    > Serial: %s " % serial
        print ""
    return 0
        

#@click.command()
#@click.option('-d', '--domain', type=str )
def digim(domain):
    domain = str('daniels.tools')
    print header("Current Whois")
    currentwhois(domain)

    print header("Zone Records")
    zonerecords(domain)

    print header("Propagation")
    get_a_records(domain)



if __name__ == '__main__':
    digim('dcwtest.com')




