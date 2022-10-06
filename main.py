import sys
hex_letters = ["a", "b", "c", "d", "e", "f"]
first_ip = ""
second_ip = ""
count = 0

# Functions:
def convert_ipv6_short(ip_number):
    ip_num_list = ip_number.split(":")
    if len(ip_num_list) == 8:
        for n in ip_num_list:
            if n == '':
                ip_num_list[ip_num_list.index(n)] = "0"
        ip_number = ':'.join(ip_num_list)
    return ip_number

def validate_ipv4(ip_number):
    """ Validates ipv4 by the rules: form "x1.x2.x3.x4" where 0 <= xi <= 255 and xi cannot contain leading zeros.
    Returns valid True or error messages."""
    global format_is_valid
    ip_num_list = ip_number.split(".")
    if len(ip_num_list) == 4:
        correct_n = 0
        for n in ip_num_list:
            try:
                int(n) and int(n[0])
            except ValueError:
                return print("Format is not valid ('n' should be between 0 and 255), please try again.")
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


def validate_ipv6(ip_number):
    """ Validates ipv6 by the rules: form "x1:x2:x3:x4:x5:x6:x7:x8" where 1 <= xi.length <= 4 xi is a hexadecimal string
     which may contain digits, lowercase and upper-case letters ('a' to 'f').Returns valid True or error messages."""
    global format_is_valid
    ip_number_converted = convert_ipv6_short(ip_number)
    ip_num_list = ip_number_converted.split(":")
    if len(ip_num_list) == 8:
        correct_n = 0
        for n in ip_num_list:
            if n == '':
                ip_num_list[ip_num_list.index(n)] = "0"
                correct_n += 1
            else:
                if len(n) in range(1, 5):
                    for x in n:
                        try:
                            if x in hex_letters or int(x) in range(10):
                                correct_n += 1
                        except ValueError:
                            return print("Format is not valid ('n' should be in hexadecimal numbers, 1-4 digits), please "
                                         "try again.")
        if correct_n == len(''.join(ip_num_list)):
            format_is_valid = True
            return
        else:
            return print("Format is not valid ('n' should be in hexadecimal numbers, 4 digits), please try again.")
    else:
        return print("Format is not valid (should be 'n1:n2:n3:n4:n5:n6:n7:n8'), please try again.")


def count_adresses(ip_type, starting_ip, ending_ip, format_divider):
    """Return IP's count in range, giving IP type - 'ipv4' or 'ipv6', two IP addresses and divider - '.' or ':'"""
    first_ip_list = starting_ip.split(format_divider)
    second_ip_list = ending_ip.split(format_divider)
    ip_count = 0
    if ip_type == 'ipv4':
        # limit - decimal numbers in one fragment including 0.
        limit = 256
        for n in range(4):
            diff = int(second_ip_list[n]) - int(first_ip_list[n])
            ip_count *= limit
            ip_count += diff
    elif ip_type == 'ipv6':
        # limit - hexadecimal numbers in one fragment including 0.
        limit = 65536
        ip_count = 0
        for n in range(8):
            diff = int(second_ip_list[n], 16) - int(first_ip_list[n], 16)
            ip_count *= limit
            ip_count += diff
    return ip_count


# 1. Choose IP type.
ip_format = input("Which IP version do you want to check? Enter IPv4 or IPv6: ").lower()

# 2. Check IPv4.
if ip_format == "ipv4":
    divider = "."
    # Enter and validate IP's.
    format_is_valid = False
    while not format_is_valid:
        first_ip = input("Enter starting IP address in format 'n1.n2.n3.n4' ('n' between 0 and 255): ")
        validate_ipv4(first_ip)
    format_is_valid = False
    while not format_is_valid:
        second_ip = input("Enter ending IP address in format 'n1.n2.n3.n4' ('n' between 0 and 255): ")
        validate_ipv4(second_ip)
    # Calculate IP's in range.
    count = count_adresses(ip_format, first_ip, second_ip, divider)

# 3. Check IPv6.
elif ip_format == "ipv6":
    divider = ':'
    # Enter and validate IP's.
    format_is_valid = False
    while not format_is_valid:
        first_ip = input("Enter starting IP address in format 'n1:n2:n3:n4:n5:n6:n7:n8' ('n' in hexadecimal between "
                         "0000 and ffff): ").lower()
        validate_ipv6(first_ip)
    format_is_valid = False
    while not format_is_valid:
        second_ip = input("Enter ending IP address in format 'n1:n2:n3:n4:n5:n6:n7:n8' ('n' in hexadecimal between "
                          "0000 and ffff): ").lower()
        validate_ipv6(second_ip)
    # Calculate IP's in range.
    ip_first_converted = convert_ipv6_short(first_ip)
    ip_second_converted = convert_ipv6_short(second_ip)
    count = count_adresses(ip_format, ip_first_converted, ip_second_converted, divider)
else:
    print("Enter IPv4 or IPv6, please try again. ")
    exit()

# 4. Check if ending address is greater than starting and display calculation or error message.
if count > 0:
    print("Your checked IP's are: {0} - {1}. The number of addresses between them are: {2}, excluding the ending one.".format(first_ip, second_ip, count))
else:
    print("The ending address must be greater than the starting one. Please try again.")


# Documentation.
'''A valid IPv4 address is an IP in the form "x1.x2.x3.x4" where 0 <= xi <= 255 and xi cannot contain leading zeros. 
For example, "192.168.1.1" and "192.168.1.0" are valid IPv4 addresses while "192.168.01.1", "192.168.1.00", 
and "192.168@1.1" are invalid IPv4 addresses. 

A valid IPv6 address is an IP in the form "x1:x2:x3:x4:x5:x6:x7:x8" where:

1 <= xi.length <= 4 xi is a hexadecimal string which may contain digits, lowercase English letter ('a' to 'f') and 
upper-case English letters ('A' to 'F'). Leading zeros are allowed in xi. For example, 
"2001:0db8:85a3:0000:0000:8a2e:0370:7334" and "2001:db8:85a3:0:0:8A2E:0370:7334" are valid IPv6 addresses, 
while "2001:0db8:85a3::8A2E:037j:7334" and "02001:0db8:85a3:0000:0000:8a2e:0370:7334" are invalid IPv6 addresses. 

 
'''
