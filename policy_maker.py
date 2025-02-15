#!/usr/bin/env python3
import sys
import json
import pandas as pd
import os
from typing import Dict, List, Any

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
            return f"${{var.default_services_path.{name}}}"  # Default service
        return name
    else:  # group
        if category:
            if category == "Infrastructure":
                return f"${{var.infra_groups_path.{name}_path}}"
            elif category == "Environment":
                return f"${{var.env_groups_path.{name}_path}}"
            elif category == "Application":
                return f"${{var.app_groups_path.{name}_path}}"
        return name

def read_input_file(filepath: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Read the input file and return policy and rules dataframes.
    """
    # Determine file type from extension
    file_extension = os.path.splitext(filepath)[1].lower()
    
    try:
        if file_extension == '.xlsx':
            policy_df = pd.read_excel(filepath, nrows=1)
            rules_df = pd.read_excel(filepath, skiprows=3)
        else:
            try:
                policy_df = pd.read_csv(filepath, nrows=1, encoding='utf-8', true_values=['TRUE', 'True', 'true'], false_values=['FALSE', 'False', 'false'])
                rules_df = pd.read_csv(filepath, skiprows=3, encoding='utf-8', true_values=['TRUE', 'True', 'true'], false_values=['FALSE', 'False', 'false'])
            except UnicodeDecodeError:
                policy_df = pd.read_csv(filepath, nrows=1, encoding='latin1', true_values=['TRUE', 'True', 'true'], false_values=['FALSE', 'False', 'false'])
                rules_df = pd.read_csv(filepath, skiprows=3, encoding='latin1', true_values=['TRUE', 'True', 'true'], false_values=['FALSE', 'False', 'false'])
    
        # Filter out any empty rows from rules
        rules_df = rules_df[rules_df['display_name'].notna()]
        
        return policy_df, rules_df
        
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

def create_policy(policy_row: pd.Series, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Create the complete policy dictionary with category validation
    """
    policy_name = policy_row.get("Terraform Policy File", policy_row.get("Application", "default-policy"))  # Use exact capitalization from input
    
    # Get category and validate it
    raw_category = policy_row.get("category", "Infrastructure")
    validated_category = validate_category(raw_category)
    
    # Create rules with category information
    rules_with_category = [
        create_rule(rule_row, validated_category) 
        for rule_row in rules
    ]
    
    # Handle sequence_number - convert 0 to empty string
    sequence_number = policy_row.get("sequence_number", 0)
    if sequence_number == 0:
        sequence_number = ""
    
    return {
        "resource": [{
            "nsxt_policy_security_policy": {
                f"{policy_name}": {
                    "nsx_id": "",
                    "display_name": policy_name,
                    "category": validated_category,
                    "comments": "" if pd.isna(policy_row.get("comments")) else policy_row.get("comments"),
                    "description": "" if pd.isna(policy_row.get("description")) else policy_row.get("description"),
                    "domain": policy_row.get("domain", "default"),
                    "locked": convert_to_bool(policy_row.get("locked", False)),
                    "sequence_number": sequence_number,
                    "rule": rules_with_category
                }
            }
        }]
    }

def create_rule(rule_row: pd.Series, category: str) -> Dict[str, Any]:
    # Create log directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    # Open log file
    with open('logs/debug.log', 'a') as log_file:
        def log(message):
            log_file.write(f"{message}\n")
            
        log(f"\nProcessing rule: {rule_row.get('display_name')}")
        
        rule = {
            "action": rule_row.get("action", "ALLOW"),
            "description": "",
            "destination_groups": [],
            "destinations_excluded": convert_to_bool(rule_row.get("destinations_excluded (Negate)", False)),
            "direction": rule_row.get("direction", "IN_OUT"),
            "disabled": convert_to_bool(rule_row.get("Rule Disabled", False)),
            "display_name": str(rule_row.get("display_name", "")),
            "ip_version": rule_row.get("ip_version", "IPV4_IPV6"),
            "log_label": "",
            "logged": convert_to_bool(rule_row.get("logged", False)),
            "notes": "",
            "sequence_number": int(rule_row.get("sequence_number", 0)),
            "services": [],
            "source_groups": [],
            "sources_excluded": convert_to_bool(rule_row.get("sources_excluded (Negate)", False)),
            "scope": []
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
    
    # Ensure output directory exists
    if not os.path.exists("output"):
        os.makedirs("output")
    
    try:
        # Read the input file
        policy_df, rules_df = read_input_file(input_path)
        
        # Create rules list
        rules = [row for _, row in rules_df.iterrows()]
        
        # Create the complete policy
        policy = create_policy(policy_df.iloc[0], rules)
        
        # Generate output filename using Terraform Policy File field
        output_file = os.path.join("output", f"{policy_df.iloc[0].get('Terraform Policy File')}.tf.json")
        
        # Check if file exists and confirm overwrite
        if check_and_confirm_overwrite(output_file):
            # Write the JSON file
            with open(output_file, 'w') as f:
                json.dump(policy, f, indent=2)
            print(f"Successfully created {output_file}")
        else:
            print("Operation cancelled by user")
            sys.exit(0)
            
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()