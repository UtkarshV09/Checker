import dns.resolver


def check_spf_published(domain):

    try:
        spf_record = dns.resolver.query(domain, 'TXT')
        for record in spf_record:
            if 'v=spf1' in record.strings[0].decode():
                return True
    except dns.resolver.NoAnswer:
        pass
    return False


def check_spf_deprecated(domain):
 
    try:
        spf_record = dns.resolver.query(domain, 'TXT')
        for record in spf_record:
            if 'v=spf1' not in record.strings[0].decode():
                return True
    except dns.resolver.NoAnswer:
        pass
    return False


def check_spf_included_lookups(domain):

    try:
        spf_record = dns.resolver.query(domain, 'TXT')
        for record in spf_record:
            if 'v=spf1' in record.strings[0].decode():
                spf_parts = record.strings[0].decode().split()
                for spf_part in spf_parts:
                    if spf_part.startswith('include:'):
                        include_domain = spf_part.split(':')[1]
                        if not check_spf_published(include_domain):
                            return False
                return True
    except dns.resolver.NoAnswer:
        pass
    return False


def check_spf_mx_resource_records(domain):
 
    try:
        mx_records = dns.resolver.query(domain, 'MX')
        spf_record = dns.resolver.query(domain, 'TXT')
        for record in spf_record:
            if 'v=spf1' in record.strings[0].decode():
                spf_parts = record.strings[0].decode().split()
                for mx_record in mx_records:
                    mx_hostname = mx_record.exchange.to_text().rstrip('.')
                    if 'mx:' + mx_hostname not in spf_parts:
                        return False
                return True
    except dns.resolver.NoAnswer:
        pass
    return False


def check_spf_type_ptr(domain):
 
    try:
        spf_record = dns.resolver.query(domain, 'TXT')
        for record in spf_record:
            if 'v=spf1' in record.strings[0].decode():
                spf_parts = record.strings[0].decode().split()
                for spf_part in spf_parts:
                    if spf_part.startswith('ptr:'):
                        ptr_domain = spf_part.split(':')[1]
                        ptr_record = dns.resolver.query(ptr_domain, 'PTR')
                        for record in ptr_record:
                            if domain in record.to_text():
                                return True
                return False
    except dns.resolver.NoAnswer:
        pass
    return False
