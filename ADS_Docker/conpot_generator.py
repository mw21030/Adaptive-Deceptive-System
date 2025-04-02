import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import random
import os
import random
from vendor import PRODUCTS_DATA


def get_random_vendor_data(port):
    port_str = str(port)  
    if port_str in PRODUCTS_DATA:
        return random.choice(PRODUCTS_DATA[port_str])
    return {}

def template_generator(port, template_name, profile_detail):
        # Create root element
        root = ET.Element("core")
        
        # Create template element with entity information
        template = ET.SubElement(root, "template")
        
        if port == 44818:
            protocol = "ENIP"
            unit = profile_detail['unit']
            vendor = profile_detail['vendor']
            description = vendor + " " + unit +"with ENIP interface"
        elif port == 102:
            protocol = "s7comm"
            unit = profile_detail['deviceName']
            vendor = profile_detail['Vendor']
            description = vendor + " " + unit +"with S7comm interface"
        elif port == 502:
            protocol = "MODBUS"
            unit = profile_detail['ProductName']
            vendor = profile_detail['Vendor']
            description = vendor + " " + unit +"with Modbus interface"

        ET.SubElement(template, "entity", attrib={"name": "unit"}).text = unit 
        ET.SubElement(template, "entity", attrib={"name": "vendor"}).text = vendor
        ET.SubElement(template, "entity", attrib={"name": "description"}).text = description
        ET.SubElement(template, "entity", attrib={"name": "protocols"}).text = protocol
        ET.SubElement(template, "entity", attrib={"name": "creator"}).text = "mw21030"
        
        # Create databus element
        databus = ET.SubElement(root, "databus")
        key_value_mappings = ET.SubElement(databus, "key_value_mappings")
        
        # Add common keys across protocols
        keys = {
            "SystemName": f"\"PLC_{random.randint(0,10)}\"",
            "FacilityName":"Bristol Food Factory",
            "Uptime": "conpot.emulators.misc.uptime.Uptime"
        }
        
        # Add protocol-specific keys
        if port == 102:  # S7comm
            keys.update({
                "SystemDescription": "\"" + profile_detail['deviceName'] + "\"",
                "sysObjectID": "\"0.0\"",
                "sysContact": "\"Siemens AG\"",
                "sysName": "\"" + profile_detail['sysName'] + "\"",
                "module": "\"" + profile_detail['sysName'] + "\"",
                "hardware": "\"" + profile_detail['sysName'] + "\"",
                "firmware": "\""+ profile_detail['firmware'] + "\"",
                "sysLocation": f"\"Level {random.randint(1, 9)}, Rack {random.randint(1, 20)}\"",
                "Copyright": "\"Original Siemens Equipment\"",
                "s7_id": "\""+ profile_detail['s7_id'] + "\"",
                "s7_module_type": "\"" + profile_detail['module_type'] + "\"",
                "empty": "\"\""
            })
            # Add memory blocks for S7
            for block in ["memoryModbusSlave0BlockA", "memoryModbusSlave0BlockB", 
                          "memoryModbusSlave255BlockA", "memoryModbusSlave255BlockB",
                          "memoryModbusSlave1BlockA", "memoryModbusSlave1BlockB",
                          "memoryModbusSlave2BlockC", "memoryModbusSlave2BlockD"]:
                if block.endswith("D"):
                    keys[block] = "[0 for b in range(0,32)]"
                elif block.endswith("C"):
                    keys[block] = "[random.randint(0,1) for b in range(0,8)]"
                elif block.endswith("B"):
                    keys[block] = "[random.randint(0,1) for b in range(0,32)]"
                else:
                    keys[block] = "[random.randint(0,1) for b in range(0,128)]"
        
        elif port == 44818:  # ENIP
            keys.update({
                "SystemDescription": "\"" + profile_detail["unit"] + " PLC\"",
                "sysObjectID": f"\" {random.randomint(1,255)}\""
            })
        
        # Create key elements in XML
        for key_name, value_data in keys.items():
            key = ET.SubElement(key_value_mappings, "key", attrib={"name": key_name})
            if "conpot.emulators" in value_data:
                ET.SubElement(key, "value", attrib={"type": "function"}).text = value_data
            else:
                ET.SubElement(key, "value", attrib={"type": "value"}).text = value_data
        
        return pretty_xml(root)

def dockerfile_generator(port, template_name):

    # Create the Dockerfile content
    dockerfile = f"""FROM my_custom_conpot_image:latest

    RUN mkdir -p /usr/local/lib/python3.10/site-packages/conpot/templates/{template_name}
        
    # Copy our custom template
    COPY . /usr/local/lib/python3.10/site-packages/conpot/templates/{template_name}

    ENV CONPOT_HOME=/opt/conpot

    # Expose the port
    EXPOSE {port}

    # Run Conpot with our template
    CMD ["conpot", "-f", "--template", "/usr/local/lib/python3.10/site-packages/conpot/templates/{template_name}"]
    """
    return dockerfile

def pretty_xml(element):
    rough_string = ET.tostring(element, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")

def generate_enip_xml(ip, vendor, port, profile_detail):
    root = ET.Element("enip", attrib={"enabled": "True", "host": ip, "port": str(port)})
    
    # Device information
    device_info = ET.SubElement(root, "device_info")
    # Use profile_detail for device information
    vendor_name = profile_detail
    
    ET.SubElement(device_info, "VendorId").text = profile_detail.get('unit', 'Generic PLC')
    ET.SubElement(device_info, "ProductName").text = profile_detail.get('unit', 'Generic PLC')
    ET.SubElement(device_info, "DeviceType").text = profile_detail.get('product_code', str(random.randint(1000, 9999)))
    ET.SubElement(device_info, "SerialNumber").text = profile_detail.get('revision', f"{random.randint(1, 5)}.{random.randint(0, 9)}")
    ET.SubElement(device_info, "ProductRevision").text = profile_detail.get('serial', str(random.randint(10000000, 99999999)))
    ET.SubElement(device_info, "ProductCode").text = profile_detail.get('serial', str(random.randint(10000000, 99999999)))
    
    # Additional ENIP settings (using sample static values; adjust as needed)
    mode = ET.SubElement(root, "mode")
    mode.text = random.choice(["tcp", "udp"])
    
    latency = ET.SubElement(root, "latency")
    latency.text = random.randrange(0,0.5 )
    
    timeout = ET.SubElement(root, "timeout")
    timeout.text = "20"
    
    # Example tags (customize as needed)
    tags = ET.SubElement(root, "tags")
    tag_data = [
        {"name": "SensorInput", "type": "BOOL", "size": "1", "value": "0", "addr": "22/1/1"},
        {"name": "SensorOutput", "type": "INT", "size": "1", "value": "67", "addr": "22/1/2"},
        {"name": "MotorSpeedControl", "type": "REAL", "size": "4", "value": "1500", "addr": "22/1/3"}
    ]
    for td in tag_data:
        tag = ET.SubElement(tags, "tag", attrib={"name": td["name"]})
        for k in ["type", "size", "value", "addr"]:
            elem = ET.SubElement(tag, k)
            elem.text = td[k]
    
    return pretty_xml(root)

def generate_s7comm_xml(ip, vendor, port):
    # Create root element for S7comm.
    root = ET.Element("s7comm", attrib={"enabled": "True", "host": ip, "port": str(port)})
    
    system_status_lists = ET.SubElement(root, "system_status_lists")
    
    vendor_data = VENDOR_DETAILS.get(vendor.lower(), {}).get("s7comm", {}).get("system_status", {})
    # Create first ssl element
    ssl = ET.SubElement(system_status_lists, "ssl", attrib={
        "id": vendor_data.get("ssl", {}).get("id", "default_id"),
        "name": vendor_data.get("ssl", {}).get("name", "Component Identification")
    })
    for tag in ["system_name", "module_name", "plant_ident", "copyright", "serial", "module_type_name", "oem_id", "location"]:
        tag_data = vendor_data.get("ssl", {}).get(tag, {})
        elem = ET.SubElement(ssl, tag, attrib={"id": tag_data.get("id", "")})
        elem.text = tag_data.get("value", "")
    
    # Create second ssl element
    ssl2 = ET.SubElement(system_status_lists, "ssl", attrib={
        "id": vendor_data.get("ssl2", {}).get("id", "default_id2"),
        "name": vendor_data.get("ssl2", {}).get("name", "Module Identification")
    })
    for tag in ["module_identification", "hardware_identification", "firmware_identification"]:
        tag_data = vendor_data.get("ssl2", {}).get(tag, {})
        elem = ET.SubElement(ssl2, tag, attrib={"id": tag_data.get("id", "")})
        elem.text = tag_data.get("value", "")
    
    return pretty_xml(root)

def generate_modbus_xml(ip, vendor, port):
    # Create root element for Modbus.
    root = ET.Element("modbus", attrib={"enabled": "True", "host": ip, "port": str(port)})
    
    # Device Information
    device_info = ET.SubElement(root, "device_info")
    details = VENDOR_DETAILS.get(vendor.lower(), {}).get("modbus", {}).get("device_info", {})
    for key, value in details.items():
        elem = ET.SubElement(device_info, key)
        elem.text = value
    
    # Other modbus settings
    mode = ET.SubElement(root, "mode")
    mode.text = VENDOR_DETAILS.get(vendor.lower(), {}).get("modbus", {}).get("mode", "serial")
    
    delay = ET.SubElement(root, "delay")
    delay.text = VENDOR_DETAILS.get(vendor.lower(), {}).get("modbus", {}).get("delay", "100")
    
    # Slaves and Blocks
    slaves_data = VENDOR_DETAILS.get(vendor.lower(), {}).get("modbus", {}).get("slaves", [])
    slaves = ET.SubElement(root, "slaves")
    for slave in slaves_data:
        slave_elem = ET.SubElement(slaves, "slave", attrib={"id": slave.get("id", "")})
        blocks = ET.SubElement(slave_elem, "blocks")
        for block in slave.get("blocks", []):
            block_elem = ET.SubElement(blocks, "block", attrib={"name": block.get("name", "")})
            for field in ["type", "starting_address", "size", "content"]:
                sub_elem = ET.SubElement(block_elem, field)
                sub_elem.text = block.get(field, "")
    
    return pretty_xml(root)

def generate_conpot(strategy, port, ip):
    template_name = f"{vender}_{ip}"
    template_xml = template_generator(port, template_name)
    dockerfile_content = dockerfile_generator(port, template_name)

    if port == 44818:
        protocol_name = "enip"
        xml_data = generate_enip_xml(ip, vender, port)
    elif port == 102:
        protocol_name = "s7comm"
        xml_data = generate_s7comm_xml(ip, vender, port)
    elif port == 502:
        protocol_name = "modbus"
        xml_data = generate_modbus_xml(ip, vender, port)
    
    # Create base directory
    base_dir = f"./Honeypot/Templates/{template_name}"
    os.makedirs(base_dir, exist_ok=True)
    
    with open(os.path.join(base_dir, "dockerfile"), "w") as f:
        f.write(dockerfile_content)
    
    with open(os.path.join(base_dir, "template.xml"), "w") as f:
        f.write(template_xml)
    
    # Create protocol directory inside
    protocol_dir = os.path.join(base_dir, protocol_name)
    os.makedirs(protocol_dir, exist_ok=True)
    
    # Write protocol XML file
    xml_file_path = os.path.join(protocol_dir, f"{protocol_name}.xml")
    with open(xml_file_path, "w") as f:
        f.write(xml_data)
    
    return template_name

if __name__ == "__main__":
    generate_conpot("Allen-Bradley CompactLogix", 502, f"192.168.0.0")