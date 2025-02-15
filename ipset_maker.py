import pandas as pd
import re
import sys
import os
from pathlib import Path
import win32com.client
import pythoncom
import json

def resolve_shortcut(shortcut_path):
    """Resolve Windows shortcut (.lnk) to target path."""
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(str(shortcut_path))
        return shortcut.Targetpath
    except Exception as e:
        print(f"Error resolving shortcut: {str(e)}")
        return None

def clean_ip_addresses(csv_str):
    """Clean and validate IP addresses from CSV string."""
    if pd.isna(csv_str):
        return []
    
    # Split on commas and clean each IP
    ips = [ip.strip() for ip in csv_str.split(',')]
    # Remove empty strings
    return [ip for ip in ips if ip]

def generate_hcl_locals(groups_data):
    """Generate HCL locals block with IP set definitions."""
    locals_block = ['locals {', '  ip_sets = {']
    
    for group_name, ip_addresses in groups_data.items():
        # Clean group name to be valid HCL identifier
        clean_name = re.sub(r'[^a-zA-Z0-9_-]', '_', group_name)
        
        # Format IP addresses as HCL list
        ip_list = json.dumps(ip_addresses)
        
        # Add group entry
        locals_block.append(f'    {clean_name} = {{')
        locals_block.append(f'      name = "{group_name}"')
        locals_block.append(f'      addresses = {ip_list}')
        locals_block.append('    }')
    
    locals_block.extend(['  }', '}', ''])
    return '\n'.join(locals_block)

def generate_hcl_resource():
    """Generate HCL resource block using dynamic blocks."""
    resource_block = [
        'resource "nsxt_policy_group" "ip_sets" {',
        '  for_each = local.ip_sets',
        '',
        '  display_name = each.value.name',
        '  description  = "IP Set for ${each.value.name}"',
        '  nsx_id       = each.value.name',
        '',
        '  criteria {',
        '    ipaddress_expression {',
        '      ip_addresses = each.value.addresses',
        '    }',
        '  }',
        '}',
        ''
    ]
    return '\n'.join(resource_block)

def convert_xlsx_to_hcl(input_file):
    """Convert Excel file to HCL format."""
    try:
        # Create output directory if it doesn't exist
        output_dir = Path('output')
        output_dir.mkdir(exist_ok=True)
        
        # Set output file path
        output_file = output_dir / 'app_shared_ipsets.tf'
        
        print(f"Reading input file: {input_file}")
        # Read Excel file
        df = pd.read_excel(input_file)
        
        # Process data into dictionary
        groups_data = {}
        for _, row in df.iterrows():
            if pd.isna(row['group_name']):
                continue
            
            group_name = row['group_name']
            # Use the csv column instead of ip_addresses
            ip_addresses = clean_ip_addresses(row['csv'])
            if ip_addresses:  # Only include groups with IP addresses
                groups_data[group_name] = ip_addresses
        
        # Open output file
        with open(output_file, 'w') as f:
            # Write locals block with IP set definitions
            f.write(generate_hcl_locals(groups_data))
            
            # Write resource block using for_each
            f.write(generate_hcl_resource())
                
        print(f"Successfully created HCL file: {output_file}")
        
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        sys.exit(1)

def main():
    # Check if input file is provided
    if len(sys.argv) != 2:
        print("Usage: python ipsetmaker.py <input.xlsx or shortcut.lnk>")
        sys.exit(1)
    
    # Get input filename from command line argument
    input_filename = sys.argv[1]
    
    # Construct input file path
    input_dir = Path('input')
    input_file = input_dir / input_filename
    
    # Check if input file exists
    if not input_file.exists():
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    
    # If the file is a shortcut, resolve it
    if input_file.suffix.lower() == '.lnk':
        print("Detected shortcut file, resolving target...")
        target_path = resolve_shortcut(input_file)
        if target_path:
            input_file = Path(target_path)
            print(f"Resolved shortcut to: {input_file}")
        else:
            print("Failed to resolve shortcut target")
            sys.exit(1)
    
    # Check if resolved file exists and is an Excel file
    if not input_file.exists():
        print(f"Error: Target file '{input_file}' not found")
        sys.exit(1)
    
    if not input_file.suffix.lower() in ['.xlsx', '.xls', '.xlsm']:
        print(f"Error: File '{input_file}' is not an Excel file")
        sys.exit(1)
    
    # Process the file
    convert_xlsx_to_hcl(input_file)

if __name__ == "__main__":
    main()