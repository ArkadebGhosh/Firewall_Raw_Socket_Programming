import json
while(True):
    option = input('1. Add\n2. Delete\n3. View Rules\n4. Modify\n5. Exit\n')
    if option == '1':
        choice = input('''Enter Rule choice:\n1. Restrict Protocol\n2. Restrict IPV4 Source\n3. Restrict IPV6 Source\n4. Restrict IPV4 Destination
5. Restrict IPV6 Destination\n6. Restrict Source MAC\n7. Restrict Destination MAC\n8. Restrict Source Port\n9. Restrict Destination Port
10. Restrict Port Source Range\n11. Restrict Port Destination Range\n12. Restrict IPV4 Source Wildcard\n13. \
Restrict IPV4 Destination Wildcard\n14. Exit\n''')
        f = open('rules.json')
        rules = json.load(f)
        f.close()
        if choice == '1':
            prot = input('Select protocol:\n1. IPv4\t2. IPV6\t3. TCP\t4. UDP\t5. ICMP\n')
            protocols = {'1': 'IPV4', '2': 'IPV6', '3': 'TCP', '4': 'UDP', '5': 'ICMP'}
            if protocols[prot] not in rules['restricted_protocols']:
                rules['restricted_protocols'].append(protocols[prot])
        elif choice == '2':
            ip = input('Enter IP: ')
            if ip not in rules['restricted_src_ipv4']:
                rules['restricted_src_ipv4'].append(ip)
        elif choice == '3':
            ip = input('Enter IP: ')
            if ip not in rules['restricted_src_ipv6']:
                rules['restricted_src_ipv6'].append(ip)
        elif choice == '4':
            ip = input('Enter IP: ')
            if ip not in rules['restricted_dest_ipv4']:
                rules['restricted_dest_ipv4'].append(ip)
        elif choice == '5':
            ip = input('Enter IP: ')
            if ip not in rules['restricted_dest_ipv6']:
                rules['restricted_dest_ipv6'].append(ip)
        elif choice == '6':
            ip = input('Enter MAC: ')
            if ip not in rules['restricted_src_mac']:
                rules['restricted_src_mac'].append(ip)
        elif choice == '7':
            ip = input('Enter MAC: ')
            if ip not in rules['restricted_dest_mac']:
                rules['restricted_dest_mac'].append(ip)
        elif choice == '8':
            ip = input('Enter Port No: ')
            if ip not in rules['restricted_src_port']:
                rules['restricted_src_port'].append(ip)
        elif choice == '9':
            ip = input('Enter Port No: ')
            if ip not in rules['restricted_dest_port']:
                rules['restricted_dest_port'].append(ip)
        elif choice == '10':
            low = int(input('Input lower bound of source port: '))
            high = int(input('Input upper bound of source port: '))
            for i in range(low, high+1):
                rules['restricted_src_port'].append(str(i))
        elif choice == '11':
            low = int(input('Input lower bound of destination port: '))
            high = int(input('Input upper bound of destination port: '))
            for i in range(low, high+1):
                rules['restricted_dest_port'].append(str(i))
        elif choice == '12':
            ip = input('Enter IP Wildcard: ')
            rules['restricted_src_ipv4w'].append(ip)
        elif choice == '13':
            ip = input('Enter IP Wildcard: ')
            rules['restricted_dest_ipv4w'].append(ip)
        elif choice == '14':
            break
        else:
            print('Unknown option')
        f = open('rules.json', 'w')
        f.write(json.dumps(rules))
        f.close()
        print('Successfully added rule')
    elif option == '2':
        choice = input('''Enter Unrestriction choice:\n1. Allow Protocol\n2. Allow IPV4 Source\n3. Allow IPV6 Source\n4. Allow IPV4 Destination
5. Allow IPV6 Destination\n6. Allow Source MAC\n7. Allow Destination MAC\n8. Allow Source Port\n9. Allow Destination Port
10. Allow IPV4 Source Wildcard\n11. Allow IPV4 Destination Wildcard\n12. Exit\n''')
        f = open('rules.json')
        rules = json.load(f)
        f.close()
        if choice == '1':
            prot = input('Select protocol:\n1. IPv4\t2. IPV6\t3. TCP\t4. UDP\t5. ICMP')
            protocols = {1: 'IPV4', 2: 'IPV6', 3: 'TCP', 4: 'UDP', 5: 'ICMP'}
            if protocols[prot] in rules['restricted_protocols']:
                rules['restricted_protocols'].remove(protocols[prot])
        elif choice == '2':
            ip = input('Enter IP: ')
            if ip in rules['restricted_src_ipv4']:
                rules['restricted_src_ipv4'].remove(ip)
        elif choice == '3':
            ip = input('Enter IP: ')
            if ip in rules['restricted_src_ipv6']:
                rules['restricted_src_ipv6'].remove(ip)
        elif choice == '4':
            ip = input('Enter IP: ')
            if ip in rules['restricted_dest_ipv4']:
                rules['restricted_dest_ipv4'].remove(ip)
        elif choice == '5':
            ip = input('Enter IP: ')
            if ip in rules['restricted_dest_ipv6']:
                rules['restricted_dest_ipv6'].remove(ip)
        elif choice == '6':
            ip = input('Enter MAC: ')
            if ip in rules['restricted_src_mac']:
                rules['restricted_src_mac'].remove(ip)
        elif choice == '7':
            ip = input('Enter MAC: ')
            if ip in rules['restricted_dest_mac']:
                rules['restricted_dest_mac'].remove(ip)
        elif choice == '8':
            ip = input('Enter Port No: ')
            if ip in rules['restricted_src_port']:
                rules['restricted_src_port'].remove(ip)
        elif choice == '9':
            ip = input('Enter Port No: ')
            if ip in rules['restricted_dest_port']:
                rules['restricted_dest_port'].remove(ip)
        elif choice == '10':
            ip = input('Enter IP Wildcard: ')
            if ip in rules['restricted_src_ipv4w']:
                rules['restricted_src_ipv4w'].remove(ip)
        elif choice == '11':
            ip = input('Enter IP Wildcard: ')
            if ip in rules['restricted_dest_ipv4w']:
                rules['restricted_dest_ipv4w'].remove(ip)
        elif choice == '12':
            break
        else:
            print('Unknown option')
        f = open('rules.json', 'w')
        f.write(json.dumps(rules))
        f.close()
        print('Successfully removed rule')
    elif option == '3':
        f = open('rules.json')
        rules = json.load(f)
        f.close()
        print('\nRULE SET:\n')
        print('Restricted Protocols: ', ', '.join(rules['restricted_protocols']))
        print('Restricted IPV4 sources: ', ', '.join(rules['restricted_src_ipv4']))
        print('Restricted IPV4 destinations: ', ', '.join(rules['restricted_dest_ipv4']))
        print('Restricted IPV6 sources: ', ', '.join(rules['restricted_src_ipv6']))
        print('Restricted IPV6 destinations: ', ', '.join(rules['restricted_dest_ipv6']))
        print('Restricted MAC sources: ', ', '.join(rules['restricted_src_mac']))
        print('Restricted MAC destinations: ', ', '.join(rules['restricted_dest_mac']))
        print('Restricted Port sources: ', ', '.join(rules['restricted_src_port']))
        print('Restricted Port destinations: ', ', '.join(rules['restricted_dest_port']))
        print('Restricted IPV4 sources wildcards: ', ', '.join(rules['restricted_src_ipv4w']))
        print('Restricted IPV4 destinations wildcards: ', ', '.join(rules['restricted_dest_ipv4w']))
    elif option == '4':
        f = open('rules.json')
        rules = json.load(f)
        f.close()
        modch = input('1. Modify Restricted Protocols\n2. Modify Restricted IPV4 sources\n3. Modify Restricted IPV6 sources\n4. Modify Restricted IPV4 destinations\
\n5. Modify Restricted IPV6 destinations\n6. Modify Restricted MAC sources\n7. Modify Restricted MAC destinations\n8. Modify Restricted Port Sources\n\
9. Modify Restricted Port destinations\n')
        print('USE EMPTY RULE TO RESET THEM')
        if modch == '1':
            print('Enter Protocols in Text:\n1. IPV4\n2. IPV6\n3. TCP\n4. UDP\n5. ICMP')
            newrules = input('Enter list of Protocols to Restrict (Comma Separated)(Existing rules will be overwritten)\n')
            rules['restricted_protocols'] = newrules.replace(' ', '').split(',')
        elif modch == '2':
            newrules = input('Enter list of IPv4 sources to Restrict (Comma Separated)(Existing rules will be overwritten)\n')
            rules['restricted_src_ipv4'] = newrules.replace(' ', '').split(',')
        elif modch == '3':
            newrules = input('Enter list of IPv6 sources to Restrict (Comma Separated)(Existing rules will be overwritten)\n')
            rules['restricted_src_ipv6'] = newrules.replace(' ', '').split(',')
        elif modch == '4':
            newrules = input('Enter list of IPv4 destinations to Restrict (Comma Separated)(Existing rules will be overwritten)\n')
            rules['restricted_dest_ipv4'] = newrules.replace(' ', '').split(',')
        elif modch == '5':
            newrules = input('Enter list of IPv6 destinations to Restrict (Comma Separated)(Existing rules will be overwritten)\n')
            rules['restricted_dest_ipv6'] = newrules.replace(' ', '').split(',')
        elif modch == '6':
            newrules = input('Enter list of MAC sources to Restrict (Comma Separated)(Existing rules will be overwritten)\n')
            rules['restricted_src_mac'] = newrules.replace(' ', '').split(',')
        elif modch == '7':
            newrules = input('Enter list of MAC destinations to Restrict (Comma Separated)(Existing rules will be overwritten)\n')
            rules['restricted_dest_mac'] = newrules.replace(' ', '').split(',')
        elif modch == '8':
            newrules = input('Enter list of Port sources to Restrict (Comma Separated)(Existing rules will be overwritten)\n')
            rules['restricted_src_port'] = newrules.replace(' ', '').split(',')
        elif modch == '9':
            newrules = input('Enter list of Port destinations to Restrict (Comma Separated)(Existing rules will be overwritten)\n')
            rules['restricted_dest_port'] = newrules.replace(' ', '').split(',')
        f = open('rules.json', 'w')
        f.write(json.dumps(rules))
        f.close()
        print('Successfully modified rule')
    elif option == '5':
        break
