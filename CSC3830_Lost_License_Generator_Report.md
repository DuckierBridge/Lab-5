# CSC-3830 Reverse Engineering & Malware Analysis

## Disassembly Lab: Reverse Engineering Challenge - The Lost License Generator

**Target Binary:** `license_check_student.exe`  
**Student:** Carter Pearse  
**Course:** CSC-3830 Reverse Engineering & Malware Analysis

---

## Objective

The goal of this challenge was to reverse engineer the recovered `license_check_student.exe` validator, determine how it calculates a license key from a username, reconstruct the algorithm, and create a replacement key generator. The original validator was not modified or patched.

---

# 1. Locate the Validation Logic

I started by opening `license_check_student.exe` in IDA and locating the `main` function. In Graph View, I followed the program from the beginning and looked for the sections that displayed the username prompt, license-key prompt, and the strings `License accepted!` and `Invalid license.`.

The program first displays:

```text
=== Student License Validator ===
Enter username (1-63 characters, no spaces):
```

It reads the username using a format string equivalent to `%63s`. After a successful username read, the program displays:

```text
Enter license key (decimal):
```

and reads the key as an unsigned decimal integer using `%u`.

![Figure 1 - Beginning of main and username input](f489f8a3-6507-4422-9d9f-10c206b051ce.png)

**Figure 1.** Beginning of `main`, including the Student License Validator message and username input.

After the username is successfully read, execution reaches the block that asks for the decimal license key.

![Figure 2 - License key input](fb11805e-c631-41b1-9e53-775d27649229.png)

**Figure 2.** The validator asks for the license key and checks whether a numeric value was successfully read.

The most important validation block appears after both inputs have been accepted:

```asm
lea     rax, [rbp+var_50]
mov     rcx, rax
call    calculateKey
mov     [rbp+var_8], eax
mov     eax, [rbp+var_54]
cmp     [rbp+var_8], eax
jnz     short loc_14000158B
```

`var_50` contains the username. Its address is passed to `calculateKey` through `RCX`. The function returns the calculated key in `EAX`, which is saved in `var_8`.

The user's entered license key is stored in `var_54`. The program loads that value into `EAX` and executes:

```asm
cmp [rbp+var_8], eax
```

This compares the calculated key against the key entered by the user.

The next instruction is:

```asm
jnz short loc_14000158B
```

`JNZ` means **Jump if Not Zero**, which after a `cmp` means the jump occurs when the two values are not equal.

- If the values are equal, `JNZ` is not taken and the program prints `License accepted!`.
- If the values are different, `JNZ` is taken and the program prints `Invalid license.`

![Figure 3 - calculateKey call and accept/reject branch](711d9018-c36f-42db-8ebd-145dbb059893.png)

**Figure 3.** The key returned by `calculateKey` is compared with the user's key. The graph then branches to either `License accepted!` or `Invalid license.`

This identified the final license-validation logic.

---

# 2. Trace the Calculation

After finding the call to `calculateKey`, I opened the `calculateKey` function in IDA and analyzed its control-flow graph.

![Figure 4 - calculateKey function](13ff04d7-2e99-4abe-a502-2fbf589ae74e.png)

**Figure 4.** Complete `calculateKey` loop showing initialization, character processing, looping, and the final XOR.

The function starts with:

```asm
mov     [rbp+arg_0], rcx
mov     [rbp+var_4], 3E8h
jmp     short loc_14000147E
```

The username pointer is passed to the function in `RCX`. The instruction:

```asm
mov [rbp+var_4], 3E8h
```

initializes the running key to hexadecimal `0x3E8`, which is **1000 decimal**.

Therefore:

```text
key = 1000
```

## Username Loop

The function checks the current username character with:

```asm
mov     rax, [rbp+arg_0]
movzx   eax, byte ptr [rax]
test    al, al
jnz     short loc_140001465
```

`movzx` loads the current character. `test al, al` checks whether that character is zero. A C string ends with a null byte (`\0`), so this creates a loop that continues until the end of the username.

In pseudocode:

```text
while current_character != '\0'
```

For each character, the function executes:

```asm
mov     rax, [rbp+arg_0]
movzx   eax, byte ptr [rax]
movzx   edx, al
mov     eax, edx
shl     eax, 3
sub     eax, edx
add     [rbp+var_4], eax
add     [rbp+arg_0], 1
```

The current character's ASCII value is placed into `EDX` and copied to `EAX`.

The instruction:

```asm
shl eax, 3
```

shifts the value left three bits, which is equivalent to multiplying it by 8:

```text
EAX = ASCII(character) * 8
```

The next instruction:

```asm
sub eax, edx
```

subtracts the original character value:

```text
(ASCII(character) * 8) - ASCII(character)
```

This simplifies to:

```text
ASCII(character) * 7
```

The program then executes:

```asm
add [rbp+var_4], eax
```

which adds that value to the running key.

Finally:

```asm
add [rbp+arg_0], 1
```

moves the username pointer forward one byte so that the next character can be processed.

Therefore, for every username character:

```text
key = key + (ASCII(character) * 7)
```

## Final XOR

When the function reaches the null terminator, it leaves the loop and executes:

```asm
mov     eax, [rbp+var_4]
xor     eax, 1234h
add     rsp, 10h
pop     rbp
retn
```

The accumulated key is moved into `EAX` and XORed with hexadecimal `0x1234`.

Therefore, the final operation is:

```text
key = key XOR 0x1234
```

The result in `EAX` is returned to `main`.

The complete recovered calculation is:

```text
Start key at 1000.

For every character in the username:
    Add ASCII(character) * 7 to the key.

After every character has been processed:
    XOR the key with 0x1234.

Return the result.
```

---

# 3. Reconstruct the Algorithm

## Recovered Pseudocode

```text
FUNCTION calculateKey(username)

    key = 1000

    FOR each character in username
        asciiValue = ASCII(character)
        key = key + (asciiValue * 7)
    END FOR

    key = key XOR 0x1234

    RETURN key

END FUNCTION
```

The validator's main logic can be represented as:

```text
INPUT username
INPUT enteredKey

expectedKey = calculateKey(username)

IF expectedKey == enteredKey
    PRINT "License accepted!"
ELSE
    PRINT "Invalid license."
END IF
```

## Assembly Instructions Used to Recover the Algorithm

| Assembly Instruction | Meaning |
|---|---|
| `mov [rbp+var_4], 3E8h` | Initialize the running key to 1000 |
| `movzx eax, byte ptr [rax]` | Read the current username character |
| `test al, al` | Check whether the current character is the null terminator |
| `jnz loc_140001465` | Continue processing if the character is not zero |
| `shl eax, 3` | Multiply the character's ASCII value by 8 |
| `sub eax, edx` | Subtract the original value, producing ASCII value times 7 |
| `add [rbp+var_4], eax` | Add the character's contribution to the running key |
| `add [rbp+arg_0], 1` | Advance to the next character |
| `xor eax, 1234h` | XOR the completed value with `0x1234` |
| `retn` | Return the calculated key in `EAX` |

## Simplified Formula

The recovered algorithm can also be expressed as:

```text
License Key = (1000 + 7 * sum(ASCII values of username characters)) XOR 0x1234
```

---

# 4. Build a Keygen

I recreated the recovered algorithm in Python. The program accepts any supported username and generates the decimal license key expected by the original executable.

## Python Source Code

```python
def calculate_key(username):
    key = 1000

    for character in username:
        key += ord(character) * 7

    key ^= 0x1234

    return key


print("=== ShieldScan License Key Generator ===")

username = input("Enter username: ")
license_key = calculate_key(username)

print("Username:", username)
print("License Key:", license_key)
```

### How the Keygen Works

1. `key` starts at `1000`.
2. Python's `ord()` function gets the numeric character value.
3. Each character value is multiplied by `7`.
4. The result is added to the running key.
5. After the username is processed, the key is XORed with `0x1234`.
6. The final value is printed in decimal because the original validator expects a decimal key.

The keygen does not modify `license_check_student.exe`.

---

# 5. Demonstrate Success

The replacement key generator must be tested against the original, unmodified validator with at least three usernames.

## Example Calculation - `Bob`

For the username:

```text
Bob
```

the ASCII values are:

```text
B = 66
o = 111
b = 98
```

Starting value:

```text
key = 1000
```

Process `B`:

```text
66 * 7 = 462
1000 + 462 = 1462
```

Process `o`:

```text
111 * 7 = 777
1462 + 777 = 2239
```

Process `b`:

```text
98 * 7 = 686
2239 + 686 = 2925
```

Final XOR:

```text
2925 XOR 0x1234 = 6489
```

Therefore:

```text
Username: Bob
Generated Key: 6489
```

Entering `Bob` and `6489` into the original validator should result in:

```text
License accepted!
```

## Required Verification Tests

Use the keygen to generate keys for three usernames and enter each username/key pair into the original `license_check_student.exe`.

### Test 1

```text
Username: ____________________
Generated Key: _______________
Validator Result: License accepted!
```

**Verification Screenshot:**  
_Insert screenshot showing Test 1 being accepted here._

### Test 2

```text
Username: ____________________
Generated Key: _______________
Validator Result: License accepted!
```

**Verification Screenshot:**  
_Insert screenshot showing Test 2 being accepted here._

### Test 3

```text
Username: ____________________
Generated Key: _______________
Validator Result: License accepted!
```

**Verification Screenshot:**  
_Insert screenshot showing Test 3 being accepted here._

> **Note:** These three screenshots should show the actual output of the unmodified validator. They should not be replaced with predicted results.

---

# Additional Input Handling Observed

While tracing `main`, I also found error-handling paths.

If the username cannot be read correctly, the program reaches a block that displays:

```text
Could not read username.
```

If the license-key input is not a valid number, the program reaches:

```text
Invalid input. Enter a numeric key.
```

![Figure 5 - Error and exit paths](02989abc-4f16-4733-b81d-2d03891eb7ae.png)

**Figure 5.** Error paths for unreadable username or invalid numeric input, along with the common exit block.

The program also contains cleanup/input-handling logic before exiting.

![Figure 6 - Exit and getchar logic](542dab8b-2021-4723-a0e8-a409e500728e.png)

**Figure 6.** Final input cleanup and exit logic used after validation.

---

# Conclusion

The license-validation mechanism was successfully recovered using IDA without modifying the original executable.

The program calculates a license key by:

1. Initializing a running value to **1000**.
2. Reading each character of the username.
3. Multiplying each character's ASCII value by **7**.
4. Adding each result to the running value.
5. XORing the completed value with **`0x1234`**.
6. Comparing the calculated result against the decimal key supplied by the user.

The final recovered formula is:

```text
License Key = (1000 + 7 * sum(ASCII(username))) XOR 0x1234
```

A Python replacement key generator was created from this algorithm. Because it reproduces the calculation instead of hard-coding a single key or modifying the validator, it can generate a valid key for any supported username.

---

# Submission Requirements Checklist

| Deliverable | Included |
|---|---|
| Technical report explaining findings | Yes |
| Annotated/relevant IDA screenshots showing key logic | Yes |
| Precise algorithm pseudocode | Yes |
| Explanation of relevant assembly instructions | Yes |
| Complete Python keygen source code | Yes |
| Original validator left unchanged | Yes |
| Three successful verification screenshots | **Still needs actual test screenshots** |

**Before final submission:** run the Python keygen for three different usernames, test all three generated keys in the original `license_check_student.exe`, and replace the three verification placeholders in Section 5 with screenshots showing `License accepted!`.
