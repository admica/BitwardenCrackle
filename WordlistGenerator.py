import itertools

# 1. CONFIGURATION
template = "#SSH0#E##"  # Your password template (use # for wildcards)
output_file = "bitwarden_wordlist.txt"

# 2. DEFINE YOUR CHARACTER STRINGS
# Simply delete characters from these strings to narrow your search.
# (Removed brackets [] and braces {} per your request)

slot1_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_+-=?"
slot2_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_+-=?"
slot3_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_+-=?"
slot4_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_+-=?"
slot5_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_+-=?"

def generate_targeted_wordlist():
    # Map the strings to a list
    slots = [slot1_chars, slot2_chars, slot3_chars, slot4_chars, slot5_chars]
    
    # Identify wildcard positions in your template
    wildcard_indices = [i for i, char in enumerate(template) if char == '#']
    num_wildcards = len(wildcard_indices)
    
    if num_wildcards > len(slots):
        print(f"Error: Template has {num_wildcards} '#' but only 5 slots defined.")
        return

    # Calculate total combinations to avoid crashing your drive with a massive file
    total_combos = 1
    for i in range(num_wildcards):
        total_combos *= len(slots[i])
    
    print(f"Template: {template}")
    print(f"Total combinations: {total_combos:,}")
    
    if total_combos > 1000000:
        print("--- WARNING ---")
        print("This will generate a VERY large text file (over 1 million lines).")
        confirm = input("Are you sure you want to proceed? (y/n): ")
        if confirm.lower() != 'y': return

    with open(output_file, "w") as f:
        # Get only the character sets needed for the number of wildcards present
        active_slots = slots[:num_wildcards]
        
        # Generate the permutations
        for combo in itertools.product(*active_slots):
            # Convert template to list to allow index replacement
            temp_list = list(template)
            for i, char in enumerate(combo):
                temp_list[wildcard_indices[i]] = char
            
            f.write("".join(temp_list) + "\n")
            
    print(f"Done! {output_file} has been created.")

if __name__ == "__main__":
    generate_targeted_wordlist()
