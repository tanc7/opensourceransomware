import sys
import os

# Configuration
KEY_SIZE = 16  # Fixed comment: Set to 16 bytes

def main():
    # 1. Input Validation
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <raw payload file>")
        sys.exit(1)

    input_file = sys.argv[1]

    # 2. Read Payload
    try:
        with open(input_file, "rb") as f:
            plaintext = f.read()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found!")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    # 3. Generate Random Key
    key = os.urandom(KEY_SIZE)

    # 4. XOR Logic (List Comprehension)
    ciphertext = bytes([plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext))])

    # 5. Output Helper Function
    def format_powershell_array(var_name, data):
        # Converts bytes to comma-separated hex strings (e.g., 0x41, 0x90)
        hex_str = ', '.join(f'0x{b:02x}' for b in data)
        print(f'{var_name} = [byte[]] @({hex_str})')

    # 6. Print Results
    format_powershell_array('$xorKey', key)
    print() # Add a newline for readability
    format_powershell_array('$xoredShellcode', ciphertext)

if __name__ == "__main__":
    main()
