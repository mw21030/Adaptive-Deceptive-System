import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

VENDOR_DETAILS = {
    "siemens": {
        "enip": {
            "VendorId": "1",
            "ProductName": "1766-L32BXBA C/21.07",
            "DeviceType": "14",
            "SerialNumber": "3491651754",
            "ProductRevision": "1557",
            "ProductCode": "21"
        },
        "s7comm": {
            "system_status": {
                "ssl": {
                    "id": "W#16#xy1C",
                    "name": "Component Identification",
                    "system_name": {"id": "W#16#0001", "value": "SystemName"},
                    "module_name": {"id": "W#16#0002", "value": "sysName"},
                    "plant_ident": {"id": "W#16#0003", "value": "FacilityName"},
                    "copyright": {"id": "W#16#0004", "value": "Copyright"},
                    "serial": {"id": "W#16#0005", "value": "s7_id"},
                    "module_type_name": {"id": "z#16#0007", "value": "s7_module_type"},
                    "oem_id": {"id": "W#16#000A", "value": "empty"},
                    "location": {"id": "W#16#000B", "value": "empty"}
                },
                "ssl2": {
                    "id": "W#16#xy11",
                    "name": "Module Identification",
                    "module_identification": {"id": "W#16#0001", "value": "module"},
                    "hardware_identification": {"id": "W#16#0006", "value": "hardware"},
                    "firmware_identification": {"id": "W#16#0006", "value": "firmware"}
                }
            }
        },
        "modbus": {
            "device_info": {
                "VendorName": "Siemens",
                "ProductCode": "SIMATIC",
                "MajorMinorRevision": "S7-200"
            },
            "mode": "serial",
            "delay": "100",
            "slaves": [
                {
                    "id": "0",
                    "blocks": [
                        {
                            "name": "memoryModbusSlave0BlockA",
                            "type": "COILS",
                            "starting_address": "1",
                            "size": "128",
                            "content": "memoryModbusSlave0BlockA"
                        },
                        {
                            "name": "memoryModbusSlave0BlockB",
                            "type": "DISCRETE_INPUTS",
                            "starting_address": "10001",
                            "size": "32",
                            "content": "memoryModbusSlave0BlockB"
                        }
                    ]
                },
                {
                    "id": "1",
                    "blocks": [
                        {
                            "name": "memoryModbusSlave255BlockA",
                            "type": "COILS",
                            "starting_address": "1",
                            "size": "128",
                            "content": "memoryModbusSlave255BlockA"
                        },
                        {
                            "name": "memoryModbusSlave255BlockB",
                            "type": "DISCRETE_INPUTS",
                            "starting_address": "10001",
                            "size": "32",
                            "content": "memoryModbusSlave255BlockB"
                        }
                    ]
                },
                {
                    "id": "255",
                    "blocks": [
                        {
                            "name": "memoryModbusSlave1BlockA",
                            "type": "COILS",
                            "starting_address": "1",
                            "size": "128",
                            "content": "memoryModbusSlave1BlockA"
                        },
                        {
                            "name": "memoryModbusSlave1BlockB",
                            "type": "DISCRETE_INPUTS",
                            "starting_address": "10001",
                            "size": "32",
                            "content": "memoryModbusSlave1BlockB"
                        }
                    ]
                }
            ]
        }
    },
    # You can add additional vendor mappings here
}

def pretty_xml(element):
    """Returns a pretty-printed XML string for the Element."""
    rough_string = ET.tostring(element, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")

def generate_enip_xml(ip, vendor, port):
    # Create root element for ENIP.
    root = ET.Element("enip", attrib={"enabled": "True", "host": ip, "port": str(port)})
    
    # Device information
    device_info = ET.SubElement(root, "device_info")
    details = VENDOR_DETAILS.get(vendor.lower(), {}).get("enip", {})
    for key, value in details.items():
        elem = ET.SubElement(device_info, key)
        elem.text = value
    
    # Additional ENIP settings (using sample static values; adjust as needed)
    mode = ET.SubElement(root, "mode")
    mode.text = "udp"
    
    latency = ET.SubElement(root, "latency")
    latency.text = "0.1"
    
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

# Example usage:
if __name__ == "__main__":
    # Generate each XML based on given ip, vendor, and port
    enip_xml = generate_enip_xml("192.168.220.13", "siemens", 44818)
    s7comm_xml = generate_s7comm_xml("192.168.220.22", "siemens", 102)
    modbus_xml = generate_modbus_xml("192.168.220.7", "siemens", 502)
    
    # Write or print the files as needed.
    with open("enip.xml", "w") as f:
        f.write(enip_xml)
    with open("s7comm.xml", "w") as f:
        f.write(s7comm_xml)
    with open("modbus.xml", "w") as f:
        f.write(modbus_xml)
    
    print("Generated XML files for ENIP, S7comm, and Modbus")