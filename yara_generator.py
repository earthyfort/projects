import hashlib
import os

# Function to generate YARA rule
def generate_yara_rule(rule_name, description, conditions):
    yara_rule = f"""rule {rule_name}  
{{
    meta:
        description = "{description}"
    
    strings:
"""
    for idx, condition in enumerate(conditions, 1):
        yara_rule += f'        $s{idx} = "{condition}"\n'

    yara_rule += """
    condition:
        any of them
}
"""
    return yara_rule

# Function to calculate file hashes
def get_file_hashes(file_path):
    hashes = {}
    with open(file_path, "rb") as f:
        file_data = f.read()
        hashes["md5"] = hashlib.md5(file_data).hexdigest()
        hashes["sha1"] = hashlib.sha1(file_data).hexdigest()
        hashes["sha256"] = hashlib.sha256(file_data).hexdigest()
    return hashes

# Main function
def main():
    print("🔹 Basic YARA Rule Generator 🔹")
    
    rule_name = input("Enter rule name: ").strip()
    description = input("Enter rule description: ").strip()
    
    print("\nChoose input type:")
    print("1. Text string pattern")
    print("2. File hash (MD5, SHA1, SHA256)")
    print("3. Hex byte sequence")
    
    choice = input("Enter choice (1-3): ").strip()
    
    conditions = []
    
    if choice == "1":
        while True:
            pattern = input("Enter text string pattern (or press Enter to finish): ").strip()
            if not pattern:
                break
            conditions.append(pattern)

    elif choice == "2":
        file_path = input("Enter file path to generate hashes: ").strip()
        if os.path.exists(file_path):
            hashes = get_file_hashes(file_path)
            print("Generated Hashes:")
            for hash_type, hash_value in hashes.items():
                print(f"{hash_type.upper()}: {hash_value}")
                conditions.append(hash_value)
        else:
            print("❌ File not found!")

    elif choice == "3":
        while True:
            hex_pattern = input("Enter hex byte pattern (e.g., 4D 5A, press Enter to finish): ").strip()
            if not hex_pattern:
                break
            conditions.append("{ " + hex_pattern + " }")

    else:
        print("❌ Invalid choice. Exiting...")
        return

    if conditions:
        yara_rule = generate_yara_rule(rule_name, description, conditions)
        print("\nGenerated YARA Rule:\n")
        print(yara_rule)

        # Save to file
        file_name = f"{rule_name}.yar"
        with open(file_name, "w") as f:
            f.write(yara_rule)
        print(f"✅ YARA rule saved as '{file_name}'")

if __name__ == "__main__":
    main()
