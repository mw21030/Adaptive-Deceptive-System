import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import random
import os
import random
from vendor import PRODUCTS_DATA

used_details = {}

def port_convert(port):
    if port == 502:
        return "modbus"
    elif port == 102:
        return "s7comm"
    elif port == 44818:
        return "enip"

def get_random_vendor_data(port):
    port_str = str(port)  
    if port_str in PRODUCTS_DATA:
        if port_str not in used_details:
            used_details[port_str] = []
        available_details = [d for d in PRODUCTS_DATA[port_str] if d not in used_details[port_str]]
        if len(available_details) < 10:
            used_details[port_str] = used_details[port_str][10:]
        detail = random.choice(available_details)
        used_details[port_str].append(detail)
        return detail
    else:
        return {}

def template_generator(ip, port, profile_detail, template_name):
    # Create root element
    root = ET.Element("core")
    
    # Create template element
    template = ET.SubElement(root, "template")
    
    # Set protocol-specific information
    if port == 44818:  # ENIP
        protocol = "ENIP"
        unit = profile_detail.get('unit', 'ControlLogix')
        vendor = profile_detail.get('Vendor', 'Allen-Bradley')
        description = f"simulation of a basic {vendor} {unit} with {protocol} in {ip}:{port}"
    elif port == 102:  # S7comm
        protocol = "s7comm"
        unit = profile_detail.get('ProductName', 'S7-1200')
        vendor = profile_detail.get('Vendor', 'Siemens')
        description = f"simulation of a basic {vendor} {unit} with {protocol} in {ip}:{port}"
    elif port == 502:  # MODBUS
        protocol = "MODBUS"
        unit = profile_detail.get('ProductName', 'Generic PLC')
        vendor = profile_detail.get('Vendor', 'Generic')
        description = f"simulation of a basic {vendor} {unit} with {protocol} in {ip}:{port}"
    
    # Add entity information
    ET.SubElement(template, "entity", attrib={"name": "unit"}).text = unit 
    ET.SubElement(template, "entity", attrib={"name": "vendor"}).text = vendor
    ET.SubElement(template, "entity", attrib={"name": "description"}).text = description
    ET.SubElement(template, "entity", attrib={"name": "protocols"}).text = protocol
    ET.SubElement(template, "entity", attrib={"name": "creator"}).text = "mw21030"
    
    # Create databus element
    databus = ET.SubElement(root, "databus")
    key_value_mappings = ET.SubElement(databus, "key_value_mappings")
    
    # Common keys for all protocols
    keys = {
        "SystemName": profile_detail.get('Vendor', 'PLC') + "_PLC" ,
        "FacilityName": "Bristol Food Factory",  # Can be made dynamic if needed
        "Uptime": "conpot.emulators.misc.uptime.Uptime"
    }
    
    # Add protocol-specific keys
    if port == 102:  # S7comm
        keys.update({
            "SystemDescription": profile_detail.get("Vendor", "Siemens") + " " + profile_detail.get('ProductName', 'Siemens PLC'),
            "sysObjectID": round(random.uniform(0.0, 9.9), 1),
            "sysContact": profile_detail.get('Vendor', 'Siemens AG') + " AG",
            "sysName": profile_detail.get('sysName', '6ES7 214-1AG40-0XB0'),
            "module": profile_detail.get('sysName', '6ES7 214-1AG40-0XB0'),
            "hardware": profile_detail.get('sysName', '6ES7 214-1AG40-0XB0'),
            "firmware": profile_detail.get('firmware', '4.5.1'),
            "sysLocation": f"Level {random.randint(1, 9)}, Rack {random.randint(1, 20)}",
            "Copyright": "Original " + profile_detail.get("Vendor", "Siemens") +" Equipment",
            "s7_id": profile_detail.get('s7_id', str(random.randint(10000000, 99999999))),
            "s7_module_type": profile_detail.get('module_type', 'CPU 1214C'),
            "empty": ""
        })
    
    elif port == 44818:  # ENIP
        keys.update({
            "SystemDescription": profile_detail.get('deviceType', 'PLC'),
            "sysObjectID": random.randint(1, 255),
            "SystemName": profile_detail.get('ProductName', 'ControlLogix'),
        })
    
    elif port == 502:  # MODBUS
        keys.update({
            "SystemDescription": profile_detail.get('ProductName', 'Modbus Device'),
            "ProductCode": profile_detail.get('ProductCode', 'MB-' + str(random.randint(1000, 9999))),
            "VendorName": profile_detail.get('Vendor', 'Generic'),
            "ProductName": profile_detail.get('ProductName', 'Modbus Device'),
            "MajorMinorRevision": profile_detail.get('firmware', '1.0'),
        })
    
    # Create key elements in XML
    for key_name, value_data in keys.items():
        key = ET.SubElement(key_value_mappings, "key", attrib={"name": key_name})
        if isinstance(value_data, str) and "conpot.emulators" in value_data:
            ET.SubElement(key, "value", attrib={"type": "function"}).text = value_data
        else:
            ET.SubElement(key, "value", attrib={"type": "value"}).text =f'"{value_data}"'
    
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

def generate_enip_xml(ip, port, profile_detail, tcp = any):
    root = ET.Element("enip", attrib={"enabled": "True", "host": ip, "port": str(port)})
    
    # Device information
    device_info = ET.SubElement(root, "device_info")
    
    ET.SubElement(device_info, "VendorId").text = profile_detail.get('VendorID', 'Generic PLC')
    ET.SubElement(device_info, "ProductName").text = profile_detail.get('ProductName', 'Generic PLC')
    ET.SubElement(device_info, "DeviceType").text = profile_detail.get('deviceType', str(random.randint(1,15)))
    ET.SubElement(device_info, "SerialNumber").text = profile_detail.get('SerialNumber', str(random.randint(1000000000, 9999999999)))
    ET.SubElement(device_info, "ProductRevision").text = profile_detail.get('ProductRevision', str(random.randint(1000,2000)))
    ET.SubElement(device_info, "ProductCode").text = profile_detail.get('ProductCode', str(random.randint(1,100)))
    
    mode = ET.SubElement(root, "mode")
    if tcp == False:
        mode.text = "udp"
    elif tcp == True:
        mode.text = "tcp"
    else:
        mode.text = random.choice(["tcp", "udp"])
    
    latency = ET.SubElement(root, "latency")
    latency.text = str(round(random.uniform(0, 0.5), 1))
    
    timeout = ET.SubElement(root, "timeout")
    timeout.text = str(random.randint(2, 20))
    

    tags = ET.SubElement(root, "tags")
    TAG_TYPES = {
        "BOOL": {"size": "1", "values": ["0", "1"]},
        "INT": {"size": "2", "min": -32768, "max": 32767},
        "REAL": {"size": "4", "min": 0, "max": 100, "decimals": True},
        "STRING": {"size": "82", "length": 10}
    }

    TAG_CATEGORIES = {
        "inputs": [
            {"tag_name": "SensorOutput", "types": ["BOOL", "INT", "REAL"]},
            {"tag_name": "SensorInput", "types": ["BOOL", "INT", "REAL"]},
            {"tag_name": "Pressure", "types": ["REAL"]},
            {"tag_name": "Temperature", "types": ["REAL"]}
        ],
        "outputs": [
            {"tag_name": "Valve", "types": ["BOOL", "INT"]},
            {"tag_name": "Motor", "types": ["BOOL", "INT", "REAL"]},
            {"tag_name": "Pump", "types": ["BOOL", "INT", "REAL"]},
            {"tag_name": "Heater", "types": ["BOOL", "INT", "REAL"]}
        ],
        "controls": [
            {"tag_name": "Speed", "types": ["INT", "REAL"]},
            {"tag_name": "Setpoint", "types": ["INT", "REAL"]},
            {"tag_name": "Mode", "types": ["INT", "BOOL"]},
            {"tag_name": "Position", "types": ["INT", "REAL"]}
        ],
        "status": [
            {"tag_name": "Status", "types": ["BOOL", "INT"]},
            {"tag_name": "Alarm", "types": ["BOOL", "INT"]},
            {"tag_name": "Error", "types": ["BOOL", "INT", "STRING"]}
        ]
    }

    def generate_random_tag_value(tag_type):
        type_info = TAG_TYPES[tag_type]
        if tag_type == "BOOL":
            return random.choice(type_info["values"])
        elif tag_type == "STRING":
            return f"\"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=random.randint(3, type_info['length'])))}\""
        elif type_info.get("decimals", False):
            return str(round(random.uniform(type_info["min"], type_info["max"]), 2))
        else:
            return str(random.randint(type_info["min"], type_info["max"]))

    def generate_random_tags(num_tags=15):
        tags = []
        addr_counter = 1
        
        # Get random categories
        categories = list(TAG_CATEGORIES.keys())
        
        for _ in range(num_tags):
            category = random.choice(categories)
            category_tags = TAG_CATEGORIES[category]
            tag_template = random.choice(category_tags)
            tag_type = random.choice(tag_template["types"])
            suffix = random.randint(1, 99)
            
            tag = {
                "name": f"{tag_template['tag_name']}",
                "type": tag_type,
                "size": TAG_TYPES[tag_type]["size"],
                "value": generate_random_tag_value(tag_type),
                "addr": f"{random.randint(10, 40)}/{random.randint(1, 9)}/{addr_counter}"
            }
            
            addr_counter += 1
            tags.append(tag)
        
        return tags

    tag_data = generate_random_tags(random.randint(8, 15))
    for td in tag_data:
        tag = ET.SubElement(tags, "tag", attrib={"name": td["name"]})
        for k in ["type", "size", "value", "addr"]:
            elem = ET.SubElement(tag, k)
            elem.text = td[k]
    
    return pretty_xml(root)

def generate_s7comm_xml(ip, port, profile_detail,template_name):
    root = ET.Element("s7comm", attrib={"enabled": "True", "host": ip, "port": str(port)})    
    system_status_lists = ET.SubElement(root, "system_status_lists")

    # Create first ssl element
    ssl = ET.SubElement(system_status_lists, "ssl", attrib={
        "id": "W#16#xy1C",
        "name": "Component Identification"
    })
    # System name
    ET.SubElement(ssl, "system_name", attrib={"id": "W#16#0001"}).text = "SystemName"
    # Module name
    ET.SubElement(ssl, "module_name", attrib={"id": "W#16#0002"}).text = "sysName"
    # Plant identification
    ET.SubElement(ssl, "plant_ident", attrib={"id": "W#16#0003"}).text = "FacilityName"
    # Copyright
    ET.SubElement(ssl, "copyright", attrib={"id": "W#16#0004"}).text = "Copyright"
    # Serial number
    ET.SubElement(ssl, "serial", attrib={"id": "W#16#0005"}).text = "s7_id"
    # Module type name
    ET.SubElement(ssl, "module_type_name", attrib={"id": "W#16#0007"}).text = "s7_module_type"
    ET.SubElement(ssl, "oem_id", attrib={"id": "W#16#000A"}).text = "empty"
    # Location
    ET.SubElement(ssl, "location", attrib={"id": "W#16#000B"}).text = "empty"
    
    # Create second ssl element
    ssl2 = ET.SubElement(system_status_lists, "ssl", attrib={
        "id": "W#16#xy11",
        "name": "Module Identification"
    })
    ET.SubElement(ssl2, "module_identification", attrib={"id": "W#16#0001"}).text = "module"
    ET.SubElement(ssl2, "hardware_identification", attrib={"id": "W#16#0006"}).text = "hardware"
    ET.SubElement(ssl2, "firmware_identification", attrib={"id": "W#16#0006"}).text = "firmware"
    
    return pretty_xml(root)

def generate_modbus_xml(ip, port, profile_detail, template_name):
    MODBUS_BLOCKS_LIBRARY = {
        "COILS": {  
            "common_names": ["DigitalOutput", "Valve", "Pump", "Motor", "Relay", "Switch", "Alarm"],
            "addr_ranges": [(1, 9999)],  # Common address ranges
            "sizes": [16, 32, 64, 128, 256]  # Common block sizes
        },
        "DISCRETE_INPUTS": {  # Binary inputs (1xxxx)
            "common_names": ["DigitalInput", "Sensor", "Button", "LimitSwitch", "Interlock", "EmergencyStop"],
            "addr_ranges": [(10001, 19999)],
            "sizes": [16, 32, 64, 128]
        },
        "INPUT_REGISTERS": {  # Analog inputs (3xxxx)
            "common_names": ["AnalogInput", "Temperature", "Pressure", "FlowRate", "Level", "CurrentSensor"],
            "addr_ranges": [(30001, 39999)],
            "sizes": [8, 16, 32, 64]
        },
        "HOLDING_REGISTERS": {  # Analog outputs/parameters (4xxxx)
            "common_names": ["AnalogOutput", "SetPoint", "Parameter", "Configuration", "Control", "Status"],
            "addr_ranges": [(40001, 49999)],
            "sizes": [8, 16, 32, 64, 128]
        }
    }

    # Create root element for Modbus
    root = ET.Element("modbus", attrib={"enabled": "True", "host": ip, "port": str(port)})
    
    # Device Information
    device_info = ET.SubElement(root, "device_info")
    # Add standard Modbus device info fields
    ET.SubElement(device_info, "VendorName").text = profile_detail.get("Vendor", "Siemens")
    ET.SubElement(device_info, "ProductCode").text = profile_detail.get("ProductCode", "SIMATIC")
    ET.SubElement(device_info, "MajorMinorRevision").text = profile_detail.get("ProductName", "S7-1200")
    
    # Set mode (tcp is more common in modern ICS)
    mode = ET.SubElement(root, "mode")
    mode.text = random.choice(["tcp", "serial"])
        
    # Set delay
    delay = ET.SubElement(root, "delay")
    delay.text = str(random.choice(range(10, 100)))
    
    # Create slaves section
    slaves = ET.SubElement(root, "slaves")
    
    # Generate random slave count (2-5 slaves by default)
    slave_count = random.randint(2, 5)
    
    # Always include slave ID 0 (common in Modbus)
    slave_ids = [0]
    
    # Generate additional random slave IDs (1-254)
    for _ in range(slave_count - 1):
        while True:
            new_id = random.randint(1, 254)
            if new_id not in slave_ids:
                slave_ids.append(new_id)
                break
    
    # Create each slave and its blocks
    memory_blocks = {}  # Track memory blocks for the databus
    
    for slave_id in slave_ids:
        slave = ET.SubElement(slaves, "slave", attrib={"id": str(slave_id)})
        blocks = ET.SubElement(slave, "blocks")
        
        # Determine number of blocks for this slave (1-4)
        block_count = random.randint(1, 4)
        
        # List to track used block types to avoid duplicates per slave
        used_block_types = []
        
        for b in range(block_count):
            # Select block type, trying to ensure variety
            available_types = [t for t in MODBUS_BLOCKS_LIBRARY.keys() 
                               if t not in used_block_types or len(used_block_types) >= len(MODBUS_BLOCKS_LIBRARY)]
            
            if not available_types:
                available_types = list(MODBUS_BLOCKS_LIBRARY.keys())
                
            block_type = random.choice(available_types)
            used_block_types.append(block_type)
            
            # Get block parameters from library
            type_info = MODBUS_BLOCKS_LIBRARY[block_type]
            
            # Generate name
            name_prefix = random.choice(type_info["common_names"])
            block_name = f"memory{name_prefix}Slave{slave_id}Block{chr(65+b)}"  # A, B, C, etc.
            
            # Generate address and size
            addr_range = random.choice(type_info["addr_ranges"])
            starting_address = str(random.randint(addr_range[0], addr_range[1]))
            size = str(random.choice(type_info["sizes"]))
            
            # Create block element
            block = ET.SubElement(blocks, "block", attrib={"name": block_name})
            ET.SubElement(block, "type").text = block_type
            ET.SubElement(block, "starting_address").text = starting_address
            ET.SubElement(block, "size").text = size
            ET.SubElement(block, "content").text = block_name
            
            # Track this memory block for databus
            memory_blocks[block_name] = {
                "type": block_type,
                "size": int(size)
            }    
    return pretty_xml(root)

def generate_conpot(port, ip, tcp = any):
    port_name = port_convert(port)
    template_name = f"{port_name}_{ip}"
    profile_detail= get_random_vendor_data(port)
    vendor = profile_detail["Vendor"]
    template_xml = template_generator(ip, port, profile_detail,template_name)
    dockerfile_content = dockerfile_generator(port, template_name)


    if port == 44818:
        protocol_name = "enip"
        xml_data = generate_enip_xml(ip, port, profile_detail,tcp)
    elif port == 102:
        protocol_name = "s7comm"
        xml_data = generate_s7comm_xml(ip, port, profile_detail, template_name)
    elif port == 502:
        protocol_name = "modbus"
        xml_data = generate_modbus_xml(ip, port, profile_detail, template_name)
    # Create base directory
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"Honeypot/Templates/{template_name}")
    os.makedirs(base_dir, exist_ok=True)
    
    with open(os.path.join(base_dir, "dockerfile"), "w") as f:
        f.write(dockerfile_content)
    
    with open(os.path.join(base_dir, "template.xml"), "w") as f:
        f.write(template_xml)
    
    protocol_dir = os.path.join(base_dir, protocol_name)
    os.makedirs(protocol_dir, exist_ok=True)
    
    xml_file_path = os.path.join(protocol_dir, f"{protocol_name}.xml")
    with open(xml_file_path, "w") as f:
        f.write(xml_data)
    
    return template_name,vendor

if __name__ == "__main__":
    generate_conpot(102,"192.168.220.0")
    generate_conpot(502,"192.168.220.0")
    generate_conpot(44818,"192.168.220.0",tcp = True)
