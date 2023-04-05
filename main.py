from spf_checker import *


if __name__ == '__main__':
    domain = 'deepstrat.in'
    print('SPF Records for: '+ domain)
    if check_spf_published(domain):
        print('SPF record found')
    else:
        print('No SPF record found')
    if not check_spf_deprecated(domain):
        print('No deprecated SPF record found')
    if check_spf_included_lookups(domain):
        print('All include lookups are valid')
    else:
        print('Invalid include lookups found')
    if check_spf_mx_resource_records(domain):
        print('All MX resource records are included')
    else:
        print('MX resource records missing')
    if check_spf_type_ptr(domain):
        print('SPF record contains a PTR type')
    else:
        print('No PTR type found in SPF record')
  
