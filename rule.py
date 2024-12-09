import re

e="""
# pass in log quick on vtnet8 inet proto tcp from 10.12.54.20 to 10.12.19.23 port 137 keep state label "0fbd41ac954f812a0378f1f34182cfb7" # : 6666666666
# pass in log quick on vtnet8 inet proto tcp from 10.12.54.20 to 10.12.19.23 port $SAP_1_PORTS keep state label "0fbd41ac954f812a0378f1f34182cfb7" # : 6666666666
# pass in log quick on vtnet8 inet proto tcp from cashbox_api to 10.12.19.23 port 137 keep state label "0fbd41ac954f812a0378f1f34182cfb7" # : 6666666666
# pass in log quick on vtnet8 inet proto tcp from cashbox_api to 10.12.19.23 port $SAP_1_PORTS keep state label "0fbd41ac954f812a0378f1f34182cfb7" # : 6666666666
# pass in log quick on vtnet8 inet proto tcp from 10.12.19.23 to pmru_rrp_pos_Hosts port 137 keep state label "0fbd41ac954f812a0378f1f34182cfb7" # : 6666666666
# pass in log quick on vtnet8 inet proto tcp from 10.12.19.23 to pmru_rrp_pos_Hosts port $SAP_1_PORTS keep state label "0fbd41ac954f812a0378f1f34182cfb7" # : 6666666666
# pass in log quick on vtnet8 inet proto tcp from cashbox_api to pmru_rrp_pos_Hosts port 137 keep state label "0fbd41ac954f812a0378f1f34182cfb7" # : 6666666666
# pass in log quick on vtnet8 inet proto tcp from cashbox_api to pmru_rrp_pos_Hosts port $SAP_1_PORTS keep state label "0fbd41ac954f812a0378f1f34182cfb7" # : 6666666666
"""
alias_results = {'10.12.54.20': ['cashbox_api', 'HAP_TEST_HOSTS']}
alias_results1 = {'10.12.19.23': ['pmru_rrp_pos_Hosts', 'rrp_pos_LB']}
aliases_by_ports22 = {'137': ['Veem2_Ports', 'SAP_1_PORTS', 'SAP_3_PORTS', 'SAP_4_Ports', 'SAP_5_Ports', 'SAP_7_Ports', 'SRQ0127777_AD_Ports_TCP_UDP', 'Ports_SAP_mgmt', 'Ports_138_137', 'Ports_VDI_lic', 'KES_to_KSC_ports_1']}

target_proto = ["tcp"]
target_ip_from = ['10.12.54.20',"cashbox_api","10.12.54.57","10.12.54.54"]
target_ip_to = ["10.12.19.23","pmru_rrp_pos_Hosts","pmasdasdasdasdasdasd"]
target_port = ["137",'SAP_1_PORTS','90']

lines = e.strip().split('\n')

found_matches = []
not_found_matches = []

for proto in target_proto:
    for ip_from in target_ip_from:
        for ip_to in target_ip_to:
            for port in target_port:
                found = False
                for line in lines:
                    #pattern = rf"(# pass|pass|block|# block)\s*(in|out)\s*log*.*proto.*?{proto}\s*.*from\s*\$*({ip_from}|\${ip_from})\s*.*to\s*\$*({ip_to}|\${ip_to})\s*.*port (.*{port}*.) keep"
                    pattern = rf"(# pass|pass|block|# block)\s*(in|out)\s*log*.*proto.*?{proto}\s*.*from\s*\$*(\b(?:{ip_from}|\${ip_from})\b)\s*.*to\s*\$*(.*?)\s*port\s*\$*(\b(?:{port}|\${port})\b)\b.*keep"
                    #pattern = rf"(# pass|pass|block|# block)\s*(in|out)\s*log*.*proto.*?{proto}\s*.*from\s*\$*({ip_from}|\${ip_from})\s*.*to\s*\$*({ip_to}|{{{ip_to}}})\s*.*port (.*{port}*.) keep"
                    #pattern = rf"(# pass|pass|block|# block)\s*(in|out)\s*log*.*proto.*?{proto}\s*.*from\s*\$*({ip_from}|{{{ip_from}}})\s*.*to\s*\$*({ip_to}|{{{ip_to}}})\s*.*port (.*{port}*.) keep"
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        action = match.group(1).replace("# pass", "dis al").replace("# block", "dis blk").replace("pass", "pass   ").replace("block", "block  ")
                        direct = match.group(2)
                        ip_from_found = match.group(3).strip('$').strip('{}')
                        ip_to_found = match.group(4).strip('$').strip('{}')
                        ip_to_port = match.group(5).strip('$').strip('{}')



                        # Обработка псевдонимов
                        resolved_ip_from = ip_from_found
                        for k, v in alias_results.items():
                            if ip_from_found in v:
                                resolved_ip_from = k
                                break
                                
                        resolved_ip_to = ip_to_found
                        
                        for k, v in alias_results1.items():
                            if ip_to_found in v:
                                resolved_ip_to = k
                                break
                        if '$' in ip_to_found: # Исправленный блок
                            for k,v in alias_results1.items():
                                if ip_to_found.strip('$') in v:
                                    resolved_ip_to = k
                                    print(resolved_ip_to,"22222222222")
                                    break

                        if '$' in ip_to_port: # Исправленный блок
                            for k,v in aliases_by_ports22.items():
                                if ip_to_port.strip('$') in v:
                                    resolved_port = k
                                    print(resolved_port,"1111111111")
                                    break


                        found_matches.append(f"Найдено совпадение:\t{action} : \t{direct}\t:{proto} \t : {ip_from_found} |<>| [{resolved_ip_from}]\t : {ip_to_found}\t [{resolved_ip_to}] {proto} {ip_to_port} {resolved_port}")
                        found = True
                if not found:
                    #not_found_matches.append(f"Не найдено совпадение :\t{action}: {direct}\t {proto} {ip_from} {ip_to} {port} {ip_to_port}")
                    not_found_matches.append(f"Не найдено совпадение :\t{action}: {direct}\t {proto} \t{ip_from} \t{ip_to} \t{port}")


print("Найденные           : a/b  : in/out : protocol :\tsource   |<>| вхождение в    : dest       :     port:")
for match in found_matches:
    print(match)

#print("\nНенайденные совпадения:")
#for match in not_found_matches:
#    print(match)
#    pattern1= r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,5})'
#    matches = re.findall(pattern, match)
#    #print(matches)


print("\nНенайденные совпадения:")
for match in not_found_matches:
    pattern2 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b\s+(?:\d{1,3}\.){3}\d{1,3}\b\s+(\d+)')
    matches = pattern2.findall(match)
    if matches:
        print(match)
