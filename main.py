
def validate_ipv4(ip_number):
    global format_is_valid
    ip_num_list = ip_number.split(".")
    if len(ip_num_list) == 4:
        correct_n = 0
        for n in ip_num_list:
            if 0 <= int(n) <= 255:
                if len(n) > 1 and int(n[0]) == 0:
                    return print("Format is not valid ('n' cannot contain leading '0'), please try again.")
                else:
                    correct_n += 1
        if correct_n == 4:
            format_is_valid = True
            return
        else:
            return print("Format is not valid ('n' should be between 0 and 255), please try again.")
    else:
        return print("Format is not valid (should be 'n1.n2.n3.n4'), please try again.")
hex_letters = ["a", "b", "c", "d", "e","f"]

def validate_ipv6(ip_number):
    global format_is_valid
    ip_num_list = ip_number.split(":")
    if len(ip_num_list) == 8:
        correct_n = 0
        for n in ip_num_list:
            if len(n) in range(1,5):
                for x in n:
                    if x in hex_letters or int(x) in range(10):
                        correct_n += 1
        if correct_n == len(''.join(ip_num_list)):
            format_is_valid = True
            return
        else:
            return print("Format is not valid, please try again.")
    else:
        return print("Format is not valid, please try again.")


ip_format = input("Which IP version do you want to check? Enter IPv4 or IPv6: ").lower()
if ip_format == "ipv4":
    format_is_valid = False
    while not format_is_valid:
        first_ip = input("Enter starting IP address in format 'n1.n2.n3.n4' ('n' between 0 and 255): ")
        validate_ipv4(first_ip)
    format_is_valid = False
    while not format_is_valid:
        second_ip = input("Enter ending IP address in format 'n1.n2.n3.n4' ('n' between 0 and 255): ")
        validate_ipv4(second_ip)

    first_ip_list = first_ip.split(".")
    second_ip_list = second_ip.split(".")
    lim = 256
    count = 0
    for n in range(4):
        diff = int(second_ip_list[n]) - int(first_ip_list[n])
        count *= lim
        count += diff

elif ip_format == "ipv6":
    format_is_valid = False
    while not format_is_valid:
        first_ip = input("Enter starting IP address in format 'n1:n2:n3:n4:n5:n6:n7:n8' ('n' in hexadecimal between 0000 and ffff): ").lower()
        validate_ipv6(first_ip)
    format_is_valid = False
    while not format_is_valid:
        second_ip = input("Enter ending IP address in format 'n1:n2:n3:n4:n5:n6:n7:n8' ('n' in hexadecimal between 0000 and ffff): ").lower()
        validate_ipv6(second_ip)
    first_ip_list = first_ip.split(":")
    second_ip_list = second_ip.split(":")
    lim = 65536 # int("ffff",16) + 1 including 0
    count = 0
    for n in range(8):
        diff = int(second_ip_list[n], 16) - int(first_ip_list[n], 16)
        count *= lim
        count += diff

# Patikrinti ar antrasis IP nėra mažesnis nei pirmasis
if count > 0:
# Patikrinti ar antrasis IP nėra mažesnis nei pirmasis
    print(f"Your checked IP's are: {first_ip} - {second_ip} \nThe number of addresses between them are: {count}")
else:
    print(f"The ending address must be greater than the starting one. Please try again.")

'''A valid IPv4 address is an IP in the form "x1.x2.x3.x4" where 0 <= xi <= 255 and xi cannot contain leading zeros. 
For example, "192.168.1.1" and "192.168.1.0" are valid IPv4 addresses while "192.168.01.1", "192.168.1.00", 
and "192.168@1.1" are invalid IPv4 addresses. 

A valid IPv6 address is an IP in the form "x1:x2:x3:x4:x5:x6:x7:x8" where:

1 <= xi.length <= 4 xi is a hexadecimal string which may contain digits, lowercase English letter ('a' to 'f') and 
upper-case English letters ('A' to 'F'). Leading zeros are allowed in xi. For example, 
"2001:0db8:85a3:0000:0000:8a2e:0370:7334" and "2001:db8:85a3:0:0:8A2E:0370:7334" are valid IPv6 addresses, 
while "2001:0db8:85a3::8A2E:037j:7334" and "02001:0db8:85a3:0000:0000:8a2e:0370:7334" are invalid IPv6 addresses. 

 
'''
