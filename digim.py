import dns.resolver
import click
import whois
import dns.zone
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *



lineoptions = {"nlines": 10, "width": 100, "ptr": None}


def pullrecord(domain, record_type):
    resolver = dns.resolver.Resolver()
    answers = resolver.query(domain, record_type.upper())
    for answer in answers:
        print 'Host', answer

def getrecords(domain):
    pullrecord(domain, "A")
    pullrecord(domain, "CNAME")
    pullrecord(domain, "MX")
    pullrecord(domain, "NS")


def header(text):
    """Prints a pretty header"""
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


@click.command()
@click.option('-d', '--domain', type=str )
def digim(domain):
    domain = str(domain)
    print header("hello world")
    print getrecords(domain)
    print currentwhois(domain)
    print zonerecords(domain)



if __name__ == '__main__':
    digim()








