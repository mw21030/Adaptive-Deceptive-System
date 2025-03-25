import os
import argparse
import ipaddress

#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

def generate_conpot_template(ip_address, vendor, port):
    # Create the root element
    root = ET.Element("core")
    
    # Add template information
    template = ET.SubElement(root, "template")
    template.set("name", f"{vendor}_template")
    
    # Add protocol details based on common industrial protocols
    protocols = ET.SubElement(root, "protocols")
    
    protocol_mapping = {
        "modbus": 502,
        "s7comm": 102,
        "http": 80,
        "snmp": 161,
        "bacnet": 47808,
        "ipmi": 623,
        "enip": 44818
    }
    
    # Vendor-specific protocols
    vendor_protocols = {
        "siemens": ["s7comm", "http", "snmp"],
        "schneider": ["modbus", "http", "snmp"],
        "allen-bradley": ["enip", "http"],
        "honeywell": ["bacnet", "http"],
        "ge": ["modbus", "http", "snmp"],
        "omron": ["fins", "http"],
        "mitsubishi": ["melsec-q", "http"]
    }
    
    # Determine protocol based on port and vendor
    protocol_name = None
    for name, default_port in protocol_mapping.items():
        if int(port) == default_port:
            protocol_name = name
            break
    
    if not protocol_name and vendor.lower() in vendor_protocols:
        protocol_name = vendor_protocols[vendor.lower()][0]
    
    if not protocol_name:
        protocol_name = "generic"
    
    protocol = ET.SubElement(protocols, protocol_name)
    protocol.set("enabled", "true")
    protocol.set("host", ip_address)
    protocol.set("port", str(port))
    
    # Add vendor-specific device information
    device_info = ET.SubElement(root, "device_info")
    vendor_elem = ET.SubElement(device_info, "vendor")
    vendor_elem.text = vendor
    
    vendor_info = {
        "siemens": {
            "product": "SIMATIC S7-300",
            "version": "v3.2.14",
            "serial": "S7-300-123456"
        },
        "schneider": {
            "product": "Modicon M340",
            "version": "v2.4.0",
            "serial": "M340-789012"
        },
        "allen-bradley": {
            "product": "ControlLogix 5570",
            "version": "v20.11",
            "serial": "CL5570-345678"
        },
        "honeywell": {
            "product": "ControlEdge PLC",
            "version": "v1.2.3",
            "serial": "CE-901234"
        },
        "ge": {
            "product": "Mark VIe",
            "version": "v5.0.1",
            "serial": "MV6-567890"
        }
    }
    
    if vendor.lower() in vendor_info:
        info = vendor_info[vendor.lower()]
        product_elem = ET.SubElement(device_info, "product")
        product_elem.text = info["product"]
        version_elem = ET.SubElement(device_info, "version")
        version_elem.text = info["version"]
        serial_elem = ET.SubElement(device_info, "serial")
        serial_elem.text = info["serial"]
    
    # Convert to pretty XML
    rough_string = ET.tostring(root, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent="  ")
    
    return pretty_xml

def generate_dockerfile(template_name, port):
    vm_path = "/usr/local/lib/python3.10/site-packages/conpot/templates/" + template_name
    template_path = os.path.basename(template_name)
    dockerfile = f"""FROM my_custom_conpot_image:latest

RUN mkdir -p {vm_path}
    
# Copy our custom template
COPY {template_path} {vm_path}

ENV CONPOT_HOME=/opt/conpot

# Expose the port
EXPOSE {port}

# Run Conpot with our template
CMD ["conpot", "-f", "--template", {vm_path}]
"""
    return dockerfile

def main():
    parser = argparse.ArgumentParser(description='Generate Conpot template and Dockerfile')
    parser.add_argument('--ip', required=True, help='IP address for the honeypot')
    parser.add_argument('--vendor', required=True, help='Vendor name (e.g., siemens, schneider)')
    parser.add_argument('--port', required=True, type=int, help='Port number for the service')
    
    args = parser.parse_args()
    
    # Validate IP address
    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        print(f"Error: '{args.ip}' is not a valid IP address")
        return
    
    # Generate template
    template_name = f"{args.vendor}_{args.port}_template.xml"
    template_content = generate_conpot_template(args.ip, args.vendor, args.port)
    
    # Write template to file
    with open(template_name, 'w') as f:
        f.write(template_content)
    
    print(f"Generated Conpot template: {template_name}")
    
    # Generate Dockerfile
    dockerfile_content = generate_dockerfile(template_name, args.port)
    
    # Write Dockerfile to file
    with open("Dockerfile", 'w') as f:
        f.write(dockerfile_content)
    
    print("Generated Dockerfile")

if __name__ == "__main__":
    main()