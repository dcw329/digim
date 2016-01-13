import dns.resolver
import click
import whois
import dns.zone
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *



options = {"nlines": 10, "width": 100, "ptr": None}


# @click.option('-r', '--record_type')
def pullrecord(domain, record_type):
    resolver = dns.resolver.Resolver()

#    print 'Checking %s...' % domain

    answers = resolver.query(domain, record_type.upper())
    for answer in answers:
        print 'Host', answer

def digim(domain):
    pullrecord(domain, "A")
#    pullrecord(domain, "cname")
    pullrecord(domain, "mx")
    pullrecord(domain, "NS")


def header(text):
    """Prints a pretty header"""
    o = options
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
    print(who.__dict__)

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

#    print "Getting zone object for domain", domain
#    zone_file = "/var/named/%s.db" % domain
#
#    try:
#        zone = dns.zone.from_file(zone_file, domain)
#        print "Zone origin:", zone.origin
#        for name, node in zone.nodes.items():
#            rdatasets = node.rdatasets
#            print "\n**** BEGIN NODE ****"
#            print "node name:", name
#            for rdataset in rdatasets:
#                print "--- BEGIN RDATASET ---"
#                print "rdataset string representation:", rdataset
#                print "rdataset rdclass:", rdataset.rdclass
#                print "rdataset rdtype:", rdataset.rdtype
#                print "rdataset ttl:", rdataset.ttl
#                print "rdataset has following rdata:"
#                for rdata in rdataset:
#                    print "-- BEGIN RDATA --"
#                    print "rdata string representation:", rdata
#                    if rdataset.rdtype == SOA:
#                        print "** SOA-specific rdata **"
#                        print "expire:", rdata.expire
#                        print "minimum:", rdata.minimum
#                        print "mname:", rdata.mname
#                        print "refresh:", rdata.refresh
#                        print "retry:", rdata.retry
#                        print "rname:", rdata.rname
#                        print "serial:", rdata.serial
#                    if rdataset.rdtype == MX:
#                        print "** MX-specific rdata **"
#                        print "exchange:", rdata.exchange
#                        print "preference:", rdata.preference
#                    if rdataset.rdtype == NS:
#                        print "** NS-specific rdata **"
#                        print "target:", rdata.target
#                    if rdataset.rdtype == CNAME:
#                        print "** CNAME-specific rdata **"
#                        print "target:", rdata.target
#                    if rdataset.rdtype == A:
#                        print "** A-specific rdata **"
#                        print "address:", rdata.address
#    except DNSException, e:
#        print e.__class__, e
#


@click.command()
@click.option('-d', '--domain')
if __name__ == '__main__':
    print header("hello world")
    print digim(domain)
    print currentwhois(domain)
    print zonerecords(domain)








