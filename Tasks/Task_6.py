import requests
import time
import sys
from requests.exceptions import ConnectionError

TARGET_URL = "https://interrato.dev/infosec/variabletime"
MESSAGE = "test_message"
NUM_BYTES = 12

session = requests.Session()

def measure_time(tag_guess_hex):
    url = f"{TARGET_URL}?message={MESSAGE}&tag={tag_guess_hex}"

    while True:
        start_time = time.perf_counter()
        try:
            response = session.get(url, timeout=5)
        except ConnectionError:
            print("CONNECTION: Aborted by the server. Pausing for 3 seconds.")
            time.sleep(3)
            continue
        except requests.exceptions.Timeout:
            print("CONNECTION: Request timeout. Pausing for 2 seconds.")
            time.sleep(2)
            continue

        end_time = time.perf_counter()

        if response.status_code == 429:
            print("NETWORK: Rate limit reached. Pausing for 2 seconds.")
            time.sleep(2)
            continue

        if response.status_code == 200:
            return float('inf'), True

        return (end_time - start_time), False


def compute_baseline(guess_test, byte_index, dummy_guesses, n_samples=10):
    dummy_times = []
    for dummy in dummy_guesses:
        guess_test[byte_index] = dummy
        hex_tag = guess_test.hex()
        measurements = []
        for _ in range(n_samples):
            elapsed, success = measure_time(hex_tag)
            if success:
                print(f"\nCOMPLETED: The correct tag is {hex_tag}")
                sys.exit(0)
            measurements.append(elapsed)
            time.sleep(0.33)
        dummy_times.append(min(measurements))
    return min(dummy_times)


def attack():
    known_tag = []
    guess_test = bytearray(NUM_BYTES)

    jump_threshold          = 0.04
    baseline_growth_threshold = 0.035
    lag_detection_margin    = 0.03

    dummy_guesses = [0x00, 0x01, 0x02]

    byte_index = 0
    baselines_history = [(0.0, False)] * NUM_BYTES
    blacklist = {i: set() for i in range(NUM_BYTES)}

    while byte_index < NUM_BYTES:
        tag_format = [hex(b) for b in known_tag]
        print(f"\nANALYZING BYTE: {byte_index} | Partial Tag: {tag_format}")

        cached_baseline, is_cached = baselines_history[byte_index]

        if is_cached:
            local_baseline = cached_baseline
            print(f"  BASELINE: Using cached value of {local_baseline:.4f}s")
        else:
            local_baseline = compute_baseline(guess_test, byte_index, dummy_guesses)
            print(f"  BASELINE: Calculated locally at {local_baseline:.4f}s")

        if byte_index > 0:
            previous_baseline, _ = baselines_history[byte_index - 1]
            growth = local_baseline - previous_baseline

            if growth < baseline_growth_threshold:
                print("  ---")
                print(f"  ERROR: Baseline grew by only {growth:.4f}s (prev {previous_baseline:.4f}s, new {local_baseline:.4f}s).")
                print(f"  BACKTRACK: Previous byte {hex(known_tag[-1])} was a false positive.")

                blacklist[byte_index - 1].add(known_tag[-1])
                known_tag.pop()
                baselines_history[byte_index] = (0.0, False)
                byte_index -= 1
                continue

        baselines_history[byte_index] = (local_baseline, True)

        candidates = []
        best_byte = -1
        found = False
        lag_triggered = False

        start_guess = 0
        if blacklist[byte_index]:
            last_fp = max(blacklist[byte_index])
            start_guess = last_fp + 1
            print(f"  RECOVERY: Restarting search from {hex(start_guess)}.")

        for guess in range(start_guess, 256):
            guess_test[byte_index] = guess
            hex_tag_to_send = guess_test.hex()

            times_for_this_guess = []
            for _ in range(5):
                elapsed, success = measure_time(hex_tag_to_send)
                if success:
                    print(f"\nCOMPLETED: The full tag is {hex_tag_to_send}")
                    sys.exit(0)
                times_for_this_guess.append(elapsed)

            clean_time = min(times_for_this_guess)

            if clean_time < local_baseline - lag_detection_margin:
                print(f"  LAG DETECTED: Clean time {clean_time:.4f}s is below baseline {local_baseline:.4f}s. Recalculating.")

                new_baseline = compute_baseline(guess_test, byte_index, dummy_guesses)
                print(f"  BASELINE: Recalculated to {new_baseline:.4f}s")

                if byte_index > 0:
                    previous_baseline, _ = baselines_history[byte_index - 1]
                    growth = new_baseline - previous_baseline

                    if growth < baseline_growth_threshold:
                        print(f"  BACKTRACK: Recalculated baseline confirms byte {hex(known_tag[-1])} was a false positive.")
                        blacklist[byte_index - 1].add(known_tag[-1])
                        known_tag.pop()
                        baselines_history[byte_index] = (0.0, False)
                        byte_index -= 1
                    else:
                        print(f"  UPDATE: Baseline set to {new_baseline:.4f}s. Restarting search.")
                        local_baseline = new_baseline
                        baselines_history[byte_index] = (local_baseline, True)
                else:
                    print(f"  UPDATE: Baseline set to {new_baseline:.4f}s. Restarting search.")
                    local_baseline = new_baseline
                    baselines_history[byte_index] = (local_baseline, True)

                lag_triggered = True
                break

            candidates.append((guess, clean_time))

            if clean_time > local_baseline + jump_threshold:
                print(f"  JUMP FOUND (Plan A): {clean_time:.4f}s for byte {hex(guess)}.")

                if byte_index + 1 < NUM_BYTES:
                    print(f"  VERIFICATION: Checking byte {hex(guess)} via next-position baseline.")
                    guess_test[byte_index] = guess
                    next_baseline = compute_baseline(guess_test, byte_index + 1, dummy_guesses)
                    growth = next_baseline - local_baseline
                    print(f"  VERIFICATION: Next baseline {next_baseline:.4f}s, growth {growth:.4f}s (threshold {baseline_growth_threshold:.4f}s).")

                    if growth >= baseline_growth_threshold:
                        print(f"  SUCCESS: Byte {hex(guess)} confirmed via baseline growth.")
                        baselines_history[byte_index + 1] = (next_baseline, True)
                        best_byte = guess
                        found = True
                        break
                    else:
                        print(f"  FALSE POSITIVE: Byte {hex(guess)} showed insufficient growth ({growth:.4f}s). Continuing search.")
                        blacklist[byte_index].add(guess)
                        continue
                else:
                    best_byte = guess
                    found = True
                    break

        if lag_triggered:
            continue

        if not found:
            print("  NO CLEAR JUMP: Sorting Plan B candidates by time and verifying sequentially.")
            candidates.sort(key=lambda x: x[1], reverse=True)

            for guess, time_val in candidates:
                if guess in blacklist[byte_index]:
                    continue

                if byte_index + 1 < NUM_BYTES:
                    print(f"  VERIFICATION (Plan B): Checking byte {hex(guess)} (time: {time_val:.4f}s).")
                    guess_test[byte_index] = guess
                    next_baseline = compute_baseline(guess_test, byte_index + 1, dummy_guesses)
                    growth = next_baseline - local_baseline
                    print(f"  VERIFICATION (Plan B): Next baseline {next_baseline:.4f}s, growth {growth:.4f}s (threshold {baseline_growth_threshold:.4f}s).")

                    if growth >= baseline_growth_threshold:
                        print(f"  SUCCESS: Plan B byte {hex(guess)} confirmed via baseline growth.")
                        baselines_history[byte_index + 1] = (next_baseline, True)
                        best_byte = guess
                        found = True
                        break
                    else:
                        print(f"  FALSE POSITIVE: Plan B byte {hex(guess)} showed insufficient growth ({growth:.4f}s).")
                        blacklist[byte_index].add(guess)
                else:
                    best_byte = guess
                    found = True
                    break

            if not found:
                print("  CRITICAL: All tested Plan B candidates failed verification. Triggering backtrack.")
                if byte_index > 0:
                    blacklist[byte_index - 1].add(known_tag[-1])
                    known_tag.pop()
                    baselines_history[byte_index] = (0.0, False)
                    byte_index -= 1
                else:
                    print("  CRITICAL: Failed at byte 0. Retrying...")
                    baselines_history[byte_index] = (0.0, False)
                continue

        print(f"FINAL CONFIRMATION: Byte {byte_index} identified as {hex(best_byte)}")
        known_tag.append(best_byte)
        guess_test[byte_index] = best_byte
        byte_index += 1


if __name__ == "__main__":
    attack()