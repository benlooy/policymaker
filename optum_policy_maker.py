#!/usr/bin/env python3
import sys
import json
import pandas as pd
import os
from typing import Dict, List, Any, Tuple

def construct_variable_reference(type_str: str, name: str, category: str = None) -> str:
    """
    Constructs variable reference based on type, name, and category
    
    Args:
        type_str: Type of reference ("service" or "group")
        name: Name of the service or group
        category: Policy category (Infrastructure, Application, or Environment)
    """
    if type_str == "service":
        if name.startswith('SVCG_'):
            return f"${{var.services_path.{name}}}"  # Custom service group
        if name.endswith('_path'):
            return f"${{var.services_base_path}}/{name}"  # We will assume the service exists
        return f"${{var.services_base_path}}/{name}"  # Default service path
    else:  # group
        if category:
            if category == "Infrastructure":
                return f"${{var.infra_groups_path.{name}_path}}"
            elif category == "Environment":
                return f"${{var.env_groups_path.{name}_path}}"
            elif category == "Application":
                return f"${{var.groups_base_path}}/{name}"  # We will assume the group exists
        return f"${{var.groups_base_path}}/{name}"  # Default group path

def read_excel_tabs(filepath: str) -> List[Tuple[pd.DataFrame, pd.DataFrame]]:
    """
    Read all tabs from the Excel file and return a list of (policy, rules) dataframe pairs.
    Each tab represents a separate policy that will be combined in order.
    """
    # Get all sheet names
    xlsx = pd.ExcelFile(filepath)
    sheet_names = xlsx.sheet_names
    policy_rules_pairs = []
    
    for sheet_name in sheet_names:
        try:
            # Read policy (first row)
            policy_df = pd.read_excel(filepath, sheet_name=sheet_name, nrows=1)
            # Read rules (skip first 3 rows)
            rules_df = pd.read_excel(filepath, sheet_name=sheet_name, skiprows=3)
            
            # Filter out any empty rows from rules
            rules_df = rules_df[rules_df['rule_display_name'].notna()]
            
            policy_rules_pairs.append((policy_df, rules_df))
            
        except Exception as e:
            print(f"Error reading sheet '{sheet_name}': {str(e)}")
            continue
    
    return policy_rules_pairs

def read_input_file(filepath: str) -> List[Tuple[pd.DataFrame, pd.DataFrame]]:
    """
    Read the input file and return a list of (policy, rules) dataframe pairs.
    For Excel files, returns multiple policies from different tabs.
    For CSV files, maintains original single-policy behavior.
    """
    # Determine file type from extension
    file_extension = os.path.splitext(filepath)[1].lower()
    
    try:
        if file_extension == '.xlsx':
            return read_excel_tabs(filepath)
        else:
            try:
                policy_df = pd.read_csv(filepath, nrows=1, encoding='utf-8', true_values=['TRUE', 'True', 'true'], false_values=['FALSE', 'False', 'false'])
                rules_df = pd.read_csv(filepath, skiprows=3, encoding='utf-8', true_values=['TRUE', 'True', 'true'], false_values=['FALSE', 'False', 'false'])
            except UnicodeDecodeError:
                policy_df = pd.read_csv(filepath, nrows=1, encoding='latin1', true_values=['TRUE', 'True', 'true'], false_values=['FALSE', 'False', 'false'])
                rules_df = pd.read_csv(filepath, skiprows=3, encoding='latin1', true_values=['TRUE', 'True', 'true'], false_values=['FALSE', 'False', 'false'])
    
            # Filter out any empty rows from rules
            rules_df = rules_df[rules_df['rule_display_name'].notna()]
            
            return [(policy_df, rules_df)]
            
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        raise

def convert_to_bool(value) -> bool:
    """
    Safely convert various input types to boolean
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.upper() == 'TRUE'
    if isinstance(value, (int, float)):
        return value == 1 or value == 1.0
    return False

def validate_category(category: str) -> str:
    """
    Validates that the category is one of the allowed values.
    Returns the category if valid with proper capitalization, raises an error if not.
    """
    valid_categories = {
        "application": "Application",
        "infrastructure": "Infrastructure",
        "environment": "Environment"
    }
    category_lower = category.lower()  # Convert to lowercase for comparison
    
    if category_lower not in valid_categories:
        raise ValueError(f"Category must be one of: {', '.join(valid_categories.values())}. Got: {category}")
    
    return valid_categories[category_lower]

def create_single_policy(policy_df: pd.DataFrame, rules_df: pd.DataFrame, existing_sequences: set = None) -> Dict[str, Any]:
    """
    Create a policy dictionary for a single policy
    
    Args:
        policy_df: DataFrame containing policy information
        rules_df: DataFrame containing rules information
        existing_sequences: Set of sequence numbers already in use
    """
    if existing_sequences is None:
        existing_sequences = set()
    rules = [row for _, row in rules_df.iterrows()]
    return create_policy(policy_df.iloc[0], rules, existing_sequences)

def create_policy(policy_row: pd.Series, rules: List[Dict[str, Any]], existing_sequences: set = None) -> Dict[str, Any]:
    """
    Create the complete policy dictionary with category validation and sequence number handling
    """
    if existing_sequences is None:
        existing_sequences = set()
        
    policy_name = policy_row.get("policy_display_name", policy_row.get("Application", "default-policy"))
    
    # Get category and validate it
    raw_category = policy_row.get("category", "Infrastructure")
    validated_category = validate_category(raw_category)
    
    # Handle sequence_number
    sequence_number = policy_row.get("sequence_number", 0)
    if isinstance(sequence_number, (int, float)):
        sequence_number = int(sequence_number)
        # If sequence number is already used, increment until we find an unused one
        while str(sequence_number) in existing_sequences:
            sequence_number += 1
        existing_sequences.add(str(sequence_number))
    
    # Create rules with category information
    rules_with_category = [
        create_rule(rule_row, validated_category) 
        for rule_row in rules
    ]
    
    return {
        "nsxt_policy_security_policy": {
            f"{policy_name}": {
                "nsx_id": "",
                "display_name": policy_name,
                "category": validated_category,
                "comments": "" if pd.isna(policy_row.get("comments")) else str(policy_row.get("comments")),
                "description": "" if pd.isna(policy_row.get("description")) else str(policy_row.get("description")),
                "domain": policy_row.get("domain", "default"),
                "locked": convert_to_bool(policy_row.get("locked", False)),
                "sequence_number": str(sequence_number),
                "rule": rules_with_category
            }
        }
    }

def create_combined_policies(policy_rules_pairs: List[Tuple[pd.DataFrame, pd.DataFrame]]) -> Dict[str, Any]:
    """
    Create a combined policy dictionary containing all policies from all tabs
    """
    # Initialize the structure with resource array
    result = {
        "resource": [{
            "nsxt_policy_security_policy": {}
        }]
    }
    
    # Process each policy and add it to the combined structure
    for policy_df, rules_df in policy_rules_pairs:
        rules = [row for _, row in rules_df.iterrows()]
        policy = create_policy(policy_df.iloc[0], rules)
        
        # Extract the policy name and content
        policy_content = policy["nsxt_policy_security_policy"]
        
        # Add each policy to the combined structure
        result["resource"][0]["nsxt_policy_security_policy"].update(policy_content)
    
    return result

def create_rule(rule_row: pd.Series, category: str) -> Dict[str, Any]:
    # Create log directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    # Open log file
    with open('logs/debug.log', 'a') as log_file:
        def log(message):
            log_file.write(f"{message}\n")
            
        log(f"\nProcessing rule: {rule_row.get('rule_display_name')}")
        
        rule = {
            "display_name": str(rule_row.get("rule_display_name", "")),
            "action": rule_row.get("action", "ALLOW"),
            "sequence_number": int(rule_row.get("sequence_number", 0)),
            "description": "",
            "source_groups": [],
            "sources_excluded": convert_to_bool(rule_row.get("sources_excluded (Negate)", False)),
            "destination_groups": [],
            "destinations_excluded": convert_to_bool(rule_row.get("destinations_excluded (Negate)", False)),
            "services": [],
            "scope": [],
            "disabled": convert_to_bool(rule_row.get("Rule Disabled", False)),
            "logged": convert_to_bool(rule_row.get("logged", False)),
            "direction": rule_row.get("direction", "IN_OUT"),
            "ip_version": rule_row.get("ip_version", "IPV4_IPV6"),
            "log_label": "",
            "notes": "",    
        }
        
        # Helper function to safely process groups
        def process_groups(value):
            if pd.isna(value) or value == "" or value == "any" or not isinstance(value, str):
                return []
            return [construct_variable_reference("group", group.strip(), category)
                   for group in value.split(',')]
        
        # Get destination groups
        rule["destination_groups"] = process_groups(rule_row.get("destination_groups"))
        
        # Get services
        services = rule_row.get("services")
        if pd.notna(services) and isinstance(services, str) and services != "" and services != "any":
            services_list = services.split(',')
            rule["services"] = [
                construct_variable_reference("service", service.strip())
                for service in services_list
            ]
        
        # Get source groups
        rule["source_groups"] = process_groups(rule_row.get("source_groups"))
        
        # Process scope (Applied To)
        scope = rule_row.get("scope (Applied To)")
        if pd.notna(scope) and isinstance(scope, str) and scope != "" and scope != "any":
            scope_groups = scope.split(',')
            rule["scope"] = [
                construct_variable_reference("group", group.strip(), category)
                for group in scope_groups
            ]
        
        return rule

def write_policy_to_file(policy: Dict[str, Any], output_dir: str, policy_name: str) -> None:
    """
    Write a single policy to its own file
    """
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate output filename
    output_file = os.path.join(output_dir, f"{policy_name}_policy.tf.json")
    
    # Wrap the policy in the required resource structure
    formatted_policy = {
        "resource": [{
            "nsxt_policy_security_policy": policy["nsxt_policy_security_policy"]
        }]
    }
    
    # Check if file exists and confirm overwrite
    if check_and_confirm_overwrite(output_file):
        with open(output_file, 'w') as f:
            json.dump(formatted_policy, f, indent=2)
        print(f"Successfully created {output_file}")
    else:
        print(f"Skipped writing {output_file}")

def check_and_confirm_overwrite(filepath: str) -> bool:
    """Check if the file exists and ask for confirmation to overwrite."""
    if os.path.exists(filepath):
        while True:
            response = input(f"The file '{filepath}' already exists. Do you want to overwrite it? (yes/no): ").strip().lower()
            if response in ['yes', 'y', '']:
                return True
            elif response in ['no', 'n']:
                return False
            print("Please answer 'yes' or 'no'")
    return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python policymaker.py <input_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    input_path = os.path.join("input", input_file)
    
    if not os.path.exists(input_path):
        print(f"Error: Input file '{input_path}' not found")
        sys.exit(1)
    
    try:
        # Read all policies from the input file
        policy_rules_pairs = read_input_file(input_path)
        
        if not policy_rules_pairs:
            print("No valid policies found in the input file")
            sys.exit(1)
        
        # Get the base application name from the first policy
        base_app_name = policy_rules_pairs[0][0].iloc[0].get("policy_display_name", "default-application").split('-')[0]
        
        # Create output directory using the base application name
        output_dir = os.path.join("output_applications", base_app_name)
        print(f"Creating output directory: {output_dir}")
        
        # Keep track of used sequence numbers
        existing_sequences = set()
        
        for policy_df, rules_df in policy_rules_pairs:
            # Get the specific policy name
            policy_name = policy_df.iloc[0].get("policy_display_name", "default-policy")
            print(f"Processing policy: {policy_name}")
            
            # Create individual policy
            policy = create_single_policy(policy_df, rules_df, existing_sequences)
            
            # Write policy to its own file
            write_policy_to_file(policy, output_dir, policy_name)
            
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        raise  # Add raise to see full traceback
        sys.exit(1)

if __name__ == "__main__":
    main()