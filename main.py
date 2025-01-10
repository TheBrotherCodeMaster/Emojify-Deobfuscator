import re
import ast
import argparse

def extract_mapping_and_encoded_data(obfuscated_code):
    """Extract the mapping dictionary and encoded data from obfuscated code."""
    try:
        obfuscated_code = obfuscated_code.replace('\r\n', '\n').strip()
        
        mapping_patterns = [
            r'(\{(?:["\']:\)|:\(|:D|:P|:\{|:\}|=\)|=\(|;\)|:S|=/|:/["\']:\s*\d+,?\s*)+\})',
            r'dict\((\[["\']:\)|:\(|:D|:P|:\{|:\}|=\)|=\(|;\)|:S|=/|:/["\']\s*,\s*\d+\],?\s*)+\)',
            r'(\{[^}]+\})'
        ]
        
        mapping_str = None
        for pattern in mapping_patterns:
            match = re.search(pattern, obfuscated_code)
            if match:
                mapping_str = match.group(1)
                break
        
        data_patterns = [
            r'for x in[\s\n]*["\']([^"\']*)["\'][\s\n]*\.split\(["\']  ["\']\)',
            r'for x in[\s\n]*["\']([^"\']*)["\'][\s\n]*(?:\.split|$)',
            r'for x in[\s\n]*"""(.*?)"""[\s\n]*\.split',
            r'for x in[\s\n]*\'\'\'(.*?)\'\'\'[\s\n]*\.split'
        ]
        
        encoded_data = None
        for pattern in data_patterns:
            match = re.search(pattern, obfuscated_code, re.DOTALL)
            if match:
                encoded_data = match.group(1).strip()
                break
        
        if not encoded_data:
            raise ValueError("Could not find encoded data")
        
        if not mapping_str:
            emoticons = set()
            for group in encoded_data.split('  '):
                emoticons.update(group.split())
            
            mapping = {}
            for i, emoticon in enumerate(sorted(emoticons)):
                mapping[emoticon] = i
            
            return mapping, encoded_data
            
        try:
            mapping_str = mapping_str.strip()
            if mapping_str.startswith('dict('):
                mapping_str = '{' + mapping_str[5:-1].replace('[', '').replace(']', '') + '}'
            
            mapping_str = mapping_str.replace("'", '"')
            
            mapping = ast.literal_eval(mapping_str)
            
            return mapping, encoded_data
            
        except Exception:
            pairs = re.findall(r'["\']([^"\']+)["\']\s*:\s*(\d+)', mapping_str)
            if pairs:
                mapping = {k: int(v) for k, v in pairs}
                return mapping, encoded_data
            
            raise ValueError("Could not parse mapping dictionary")
            
    except Exception as e:
        raise ValueError(f"Failed to parse obfuscated code: {str(e)}")

def decode_string(encoded_data, mapping):
    """Decode the obfuscated string using the mapping."""
    try:
        chunks = encoded_data.strip().split('\n')
        encoded_str = ''.join(chunk.rstrip('\\') for chunk in chunks)
        char_groups = encoded_str.split('  ')
        
        decoded = ''
        for group in char_groups:
            if not group:
                continue
            
            emoticons = group.split()
            
            numbers = []
            valid_group = True
            
            for emoticon in emoticons:
                if emoticon not in mapping:
                    valid_group = False
                    break
                numbers.append(str(mapping[emoticon]))
            
            if valid_group and numbers:
                try:
                    char_code = int(''.join(numbers))
                    decoded += chr(char_code)
                except ValueError:
                    continue
        
        return decoded
        
    except Exception as e:
        print(f"Warning: Error in decode_string: {str(e)}")
        return ""

def deobfuscate(obfuscated_code):
    """Main deobfuscation function."""
    try:
        mapping, encoded_data = extract_mapping_and_encoded_data(obfuscated_code)
        
        original_code = decode_string(encoded_data, mapping)
        
        if not original_code:
            raise ValueError("Failed to decode the obfuscated code")
            
        return original_code
        
    except Exception as e:
        return f"Error deobfuscating code: {str(e)}"

def run_argparse():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Deobfuscate Python code that was obfuscated using emoticons/emojis"
    )
    parser.add_argument("-i", "--input", required=True, help="input obfuscated python script")
    parser.add_argument("-o", "--output", required=True, help="output deobfuscated python script")
    return parser.parse_args()

def main():
    args = run_argparse()
    
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            obfuscated_code = f.read()
        
        deobfuscated_code = deobfuscate(obfuscated_code)
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(deobfuscated_code)
        
        print(f"Successfully deobfuscated code from '{args.input}' to '{args.output}'")
        
    except FileNotFoundError:
        print(f"Error: Could not find input file '{args.input}'")
    except PermissionError:
        print("Error: Permission denied when accessing files")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()