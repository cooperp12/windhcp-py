# Tested on Windows 11 and Ubuntu 22.04.1-Ubuntu with Python 3.11.5 using Windows Server 2022 (Trial)
# This code is an updated version of https://github.com/Linkk93/windhcp-py
#   To Python 3 and simplifying some code blocks. This code is by no means clean or optimised.
#   It demonstrates read and write for DHCP for Windows on any operating system.
#   Requires ssh server on the Windows Server and ssh client on the system it runs
#   python windhcp-release.py -s 192.168.XXX.XXX -u UserName

#paramiko & netaddr may require pip to be installed
import paramiko 
import sys
import os
import argparse
from netaddr import *
import pprint
import re
import ipaddress
import getpass

def is_valid_ipv4(ip):
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return re.match(ipv4_pattern, ip) is not None
    
def get_IPv4():
    netid = input("Enter DHCP Scope ID (net_id): ")
    while not is_valid_ipv4(netid):
                netid = input("Enter DHCP Scope ID (net_id): ")
    return netid
    
class windhcp:
    def SSHconnection(self, dhcpserver, username, password):
        # Establish an SSH connection to the DHCP server
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(dhcpserver, 22, username, password)
        return ssh

    def GETscopes(self, dhcpserver):
        # Retrieve DHCP scopes
        get_scopes = 'netsh dhcp server show scope'
        # Declare lists
        net_id_list = []
        netmask_list = []
        state_list = []
        scope_name_list = []
        comment_list = []
        stdin, stdout, stderr = ssh.exec_command(get_scopes)

        inside_scope_section = False  # Flag to indicate when inside the scope section
        for line in stdout.read().decode("utf-8").splitlines():
            #Print to determine the full output
            #print("Line: {}".format(line))

            # Check if the line indicates the start of the scope section
            if line.strip().startswith("Scope Address"):
                inside_scope_section = True
                continue  # Skip the header line

            # Check if we are inside the scope section and the line is not empty
            if inside_scope_section and line.strip():
                # Use regular expressions to extract data
                match = re.match(r'\s*([\d.]+)\s+-\s+([\d.]+)\s+(-\S+)\s+(-.*?)\s+(-.*)', line)
                if match:
                    net_id, netmask, state, scope_name, comment = match.groups()
                    # Clean up variables by removing leading and trailing whitespace
                    net_id = net_id.strip()
                    netmask = netmask.strip()
                    state = state.strip()
                    scope_name = scope_name.strip()
                    comment = comment.strip()
                    # Append cleaned values to lists
                    net_id_list.append(net_id)
                    netmask_list.append(netmask)
                    state_list.append(state)
                    scope_name_list.append(scope_name)
                    comment_list.append(comment)

        #print(net_id_list)
        return (net_id_list, netmask_list, state_list, scope_name_list, comment_list)

    def GETdhcpRanges(self, dhcpserver, netid):
        start_range_ip_list = []
        end_range_ip_list = []
        range_type_list = []
        get_ranges = 'netsh dhcp server scope ' + netid + ' show iprange'
        stdin, stdout, stderr = ssh.exec_command(get_ranges)
        start_range_ip = ""
        end_range_ip = ""
        
        for line in stdout.read().decode("utf-8").splitlines():
			# Select lines with hyphens (indicating IP ranges)
            if '-' in line:
				# Select lines with dots (indicating IP addresses)
                if '.' in line:
                    (start_range_ip, end_range_ip, range_type) = line.split(' - ')
                    start_range_ip = start_range_ip.strip()
                    end_range_ip = end_range_ip.strip()
                    range_type = range_type.strip()
                    start_range_ip_list.append(start_range_ip)
                    end_range_ip_list.append(end_range_ip)
                    range_type_list.append(range_type)
                    #print(start_range_ip , end_range_ip)
        return (start_range_ip_list, end_range_ip_list, range_type_list, start_range_ip, end_range_ip)

    def GETexclusions(self, dhcpserver, netid):
        start_ex_ip_list = []
        end_ex_ip_list = []
        #pairs of start/end, as there may exist many exclusions in a range
        start_end_pair = []
        get_exclusions = 'netsh dhcp server scope ' + netid + ' show excluderange'
        stdin, stdout, stderr = ssh.exec_command(get_exclusions)
        for line in stdout.read().decode("utf-8").splitlines():
			# Select lines with hyphens (indicating IP ranges)
            if '-' in line:
				# Select lines with dots (indicating IP addresses)
                if '.' in line:
                    (start_ex_ip, end_ex_ip) = line.split(' - ')
                    start_ex_ip = start_ex_ip.strip()
                    end_ex_ip = end_ex_ip.strip()
                    start_ex_ip_list.append(start_ex_ip)
                    end_ex_ip_list.append(end_ex_ip)
                    #print("Start: {} \n End: {}".format(start_ex_ip, end_ex_ip))
                    start_end_pair.append([start_ex_ip, end_ex_ip])
                    
        return (start_end_pair)
	
    def GETclients(self, dhcpserver, netid):
        get_clients = 'netsh dhcp server scope ' + netid + ' show clients'
        stdin, stdout, stderr = ssh.exec_command(get_clients)
        client_ip_list = []
        netmask_list = []
        client_mac_list = []
        expiration_list = []
        client_type_list = []
        fqdn_list = []
        for line in stdout.read().decode("utf-8").splitlines():
			# Select lines with hyphens (indicating IP ranges)
            if '-' in line:
				# Select lines with dots (indicating IP addresses)
                if '.' in line:
                    try:
                        (client_ip, netmask, client_mac, expiration, client_type) = line.split(' -')
                        client_ip = client_ip.strip()
                        netmask = netmask.strip()
                        client_mac = client_mac.strip()
                        expiration = expiration.strip()
                        client_type = client_type.strip()
                        #fqdn = fqdn.strip()
                        client_ip_list.append(client_ip)
                        netmask_list.append(netmask)
                        client_mac_list.append(client_mac)
                        expiration_list.append(expiration)
                        client_type_list.append(client_type)
						#fqdn_list.append(fqdn)
                    except:
                        print('Error in parsing')
		#print fqdn_list
        print(client_ip_list)
        return (client_ip_list, netmask_list, client_mac_list, expiration_list, client_type_list)

    def GETfreehosts(self, dhcpserver, netid):
        free_ip_list = []
        occupied_ip_list = []
        client_ip_list, netmask_list, client_mac_list, expiration_list, client_type_list = windhcp.GETclients(self, dhcpserver, netid)
		# print client_list[0]
        net_id_list, netmask_list, state_list, scope_name_list, comment_list = windhcp.GETscopes(self, dhcpserver)
        free = 0
        occupied = 0
        match = net_id_list.index(netid)
        netmask = IPAddress(netmask_list[match])  # Convert netmask to an IPAddress type for processing
        CIDR = netmask.bits().count('1')  # Count the '1's in the netmask's bits to get the CIDR of the selected subnet
        CIDR = str(CIDR)  # Convert CIDR to a string, or else it will cause issues
		# network = IPNetwork ( check_net_id + '/' + CIDR ) #setta network come tipo IP 
        for ip in IPNetwork(netid + '/' + CIDR).iter_hosts():
            ip = str(ip)
            try:
                match = client_ip_list.index(ip)
                occupied_ip_list.append(client_ip_list[match])
                occupied = occupied + 1
            except:
                free_ip_list.append(ip)
                free = free + 1
        return (occupied_ip_list, free_ip_list, free, occupied)
		
    import ipaddress

    def GETallocablehosts(self, dhcpserver, netid):
        # Get exclusion ranges
        start_end_ex = self.GETexclusions(dhcpserver, netid)
        
        # Flatten the list of exclusion ranges into a list of individual IPs
        excluded_ips = []
        for start, end in start_end_ex:
            start_ip = ipaddress.IPv4Address(start)
            end_ip = ipaddress.IPv4Address(end)
            # We may have multiple exclusion ranges
            for ip in range(int(start_ip), int(end_ip) + 1):
                excluded_ips.append(str(ipaddress.IPv4Address(ip)))
                
        #print("Excluded: {}".format(excluded_ips))

        # Get occupied and reserved IP lists
        occupied_ip_list, _, _, _ = self.GETfreehosts(dhcpserver, netid)

        # Convert the start and end IP addresses to ipaddress objects
        _, _, _, start_range_ip_str, end_range_ip_str = dhcp_manager.GETdhcpRanges(args.server, netid)
        start_range_ip = ipaddress.IPv4Address(start_range_ip_str)
        end_range_ip = ipaddress.IPv4Address(end_range_ip_str)

        # Create a list to store allocable (usable) IP addresses
        allocable_ip_list = []

        # Iterate through the IP range
        current_ip = start_range_ip
        while current_ip <= end_range_ip:
            ip_str = str(current_ip)

            # Check if the IP is in the occupied or reserved lists
            if ip_str in occupied_ip_list or ip_str in excluded_ips:
                current_ip += 1
                continue  # Skip if occupied or reserved
            
            # Check if the IP is within any exclusion range
            in_exclusion_range = False
            for start, end in start_end_ex:
                if ipaddress.IPv4Address(start) <= current_ip <= ipaddress.IPv4Address(end):
                    in_exclusion_range = True
                    break
            
            allocable_ip_list.append(ip_str)
            current_ip += 1

        # Print and return the list of allocable IP addresses
        print("\n\nAllocable IP addresses: {}\n".format(allocable_ip_list))

        return allocable_ip_list

    def ADDdhcpentry(self, dhcpserver, netid, ip_addr, mac_addr, description):
        # To add more functions like this one --> https://web.archive.org/web/20220927071610/https://techgenix.com/creatingandmanagingdhcpscopesusingnetsh/
        
        add_reservation = 'netsh dhcp server scope ' + netid + ' add reservedip ' + ip_addr + ' ' + mac_addr + ' ' + description         
        
        print("add_reservation: {}".format(add_reservation))
        stdin, stdout, stderr = ssh.exec_command(add_reservation)
        
        for line in stdout.read().decode("utf-8").splitlines():
            print(line)

    def DELETEdhcpentry(self, dhcpserver, netid, ip_addr, mac_addr):
        delete_entry = 'netsh dhcp server scope ' + netid + ' delete reservedip ' + ip_addr + ' ' + mac_addr 
        stdin, stdout, stderr = ssh.exec_command(delete_entry)
        for line in stdout.read().decode("utf-8").splitlines():
            print(line)

if __name__ == "__main__":
    net_id_list = ''
    netmask_list = ''
    state_list = ''
    scope_name_list = ''
    comment_list = ''
    
    parser = argparse.ArgumentParser(description='Manage DHCP using netsh commands over SSH')
    parser.add_argument('-s', '--server', required=True, help='DHCP server IP address')
    parser.add_argument('-u', '--username', required=True, help='SSH username')

    args = parser.parse_args()

    # Prompt for the SSH password securely
    password = getpass.getpass(prompt="Enter SSH password: ")
    
    # Create an instance of the windhcp class
    dhcp_manager = windhcp()

    # Establish an SSH connection to the DHCP server
    ssh = dhcp_manager.SSHconnection(args.server, args.username, password)

    while True:
        print("Available Actions:")
        print("1. Get DHCP Scopes")
        print("2. Get DHCP Ranges")
        print("3. Get DHCP Exclusions")
        print("4. Get DHCP Clients")
        #Could we modified to do both using the above functions
        print("5. Get IPs Allocated (Leases & Reservations)")
        print("6. Get Allocable Hosts")
        print("7. Add Reservation")
        print("8. Delete Reservation")
        print("9. Quit")

        action_choice = input("Select an action (1-9): ")

        #dhcp_manager is calling the class to call the function, everything underneath it is printing the result
        #   We don't always want the function to return, as these functions are used by other functions
        if action_choice == "1":
            net_id_list, netmask_list, state_list, scope_name_list, comment_list = dhcp_manager.GETscopes(args.server)
            print("Scopes: {}\n".format(net_id_list))
        elif action_choice == "2":
            netid = get_IPv4()
            _, _, _, start_ip, end_ip = dhcp_manager.GETdhcpRanges(args.server, netid)
            print("Start IP: {} to {}\n".format(start_ip, end_ip))
        elif action_choice == "3":
            netid = get_IPv4()
            exclusion_ip_lists = dhcp_manager.GETexclusions(args.server, netid)
            print("Excluded: {}\n".format(exclusion_ip_lists))
            for line in exclusion_ip_lists:
                print("Start of Exclusion from {} to {}".format(line[0],line[1]))
            print("\n")
        elif action_choice == "4":
            netid = get_IPv4()
            dhcp_manager.GETclients(args.server, netid)
        elif action_choice == "5":
            netid = get_IPv4()
            dhcp_manager.GETfreehosts(args.server, netid)
        elif action_choice == "6":
            netid = get_IPv4()
            dhcp_manager.GETallocablehosts(args.server, netid)
        elif action_choice == "7":
            #IPv4 Address scope
            netid = get_IPv4()
            ip_addr = input("Enter IP Address for Reservation: ")
            print("MAC Address must 12 hexadecimal digits without \":\" OR \"-\" OR anything else.")
            mac_addr = input("Enter MAC Address for Reservation: ")
            #Name of ther device.
            description = input("Enter Description for Reservation (Name): ")
            
            dhcp_manager.ADDdhcpentry(args.server, netid, ip_addr, mac_addr, description)
        elif action_choice == "8":
            netid = get_IPv4()
            ip_addr = input("Enter IP Address to Delete: ")
            mac_addr = input("Enter MAC Address to Delete: ")
            dhcp_manager.DELETEdhcpentry(args.server, netid, ip_addr, mac_addr)
        elif action_choice == "9":
            break
        else:
            print("Invalid choice. Please select a valid action (1-9).")

ssh.close()
