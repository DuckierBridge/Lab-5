[CSC3830_Lost_License_Generator_Report_Embedded_Images.md](https://github.com/user-attachments/files/32260629/CSC3830_Lost_License_Generator_Report_Embedded_Images.md)



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

<img width="983" height="553" alt="Screenshot 2026-09-15 154243" src="https://github.com/user-attachments/assets/4925cab0-bd97-464e-b0fb-ec9373bed8fc" />

**Figure 1.** Beginning of `main`, including the Student License Validator message and username input.

After the username is successfully read, execution reaches the block that asks for the decimal license key.

<img width="1008" height="443" alt="Screenshot 2026-09-15 154342" src="https://github.com/user-attachments/assets/df7cb1ee-25d9-4910-a483-89839a040302" />

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

<img width="1003" height="548" alt="Screenshot 2026-09-15 154359" src="https://github.com/user-attachments/assets/6e5c46e3-2664-44ec-8f33-d3c7870f21dc" />

**Figure 3.** The key returned by `calculateKey` is compared with the user's key. The graph then branches to either `License accepted!` or `Invalid license.`

This identified the final license-validation logic.

---


## Main Function Path Summary

The `main` function is mainly responsible for input and for deciding whether the key is accepted. Its normal path is:

```text
Start
  |
  v
Display Student License Validator
  |
  v
Read username with %63s
  |
  +---- read fails ----> "Could not read username." ----> Exit
  |
  v
Read decimal license key with %u
  |
  +---- read fails ----> "Invalid input. Enter a numeric key." ----> Exit
  |
  v
call calculateKey(username)
  |
  v
Calculated key returned in EAX
  |
  v
Compare calculated key with entered key
  |
  +---- equal ---------> "License accepted!"
  |
  +---- not equal -----> "Invalid license."
  |
  v
Exit
```

The important point is that `main` does **not** create the key itself. The actual license-generation algorithm is contained in `calculateKey`, so that function was the main focus of the reverse engineering.


# 2. Trace the Calculation - `calculateKey`

After locating `call calculateKey` in `main`, I opened the function in IDA. This function contains the actual algorithm used to generate the expected license key from the username.

<img width="848" height="553" alt="Screenshot 2026-09-15 154959" src="https://github.com/user-attachments/assets/eefdd467-c054-4137-b063-1d6bcad90ce7" />

**Figure 4.** The `calculateKey` function initializes the key, loops through each username character, and applies a final XOR.

The function first saves the username pointer and initializes the running key:

```asm
mov     [rbp+arg_0], rcx
mov     [rbp+var_4], 3E8h
```

`RCX` contains the username address, and `0x3E8` is **1000 decimal**, so the calculation begins with:

```text
key = 1000
```

The function then checks each character:

```asm
movzx   eax, byte ptr [rax]
test    al, al
jnz     short loc_140001465
```

`test al, al` checks for the null terminator (`\0`). If the character is not zero, the loop processes it.

The main calculation for each character is:

```asm
movzx   edx, al
mov     eax, edx
shl     eax, 3
sub     eax, edx
add     [rbp+var_4], eax
add     [rbp+arg_0], 1
```

`shl eax, 3` multiplies the character value by 8. The following `sub eax, edx` subtracts the original character value, making the result **character value × 7**. That result is added to the running key. The username pointer is then increased by one so the next character can be processed.

Therefore, each loop performs:

```text
key = key + (ASCII(character) * 7)
```

Once the null terminator is reached, the function performs:

```asm
mov     eax, [rbp+var_4]
xor     eax, 1234h
```

This XORs the accumulated value with `0x1234`. XOR compares the two numbers bit-by-bit: matching bits produce `0` and different bits produce `1`. The resulting value in `EAX` is the final license key returned to `main`.

The recovered calculation is:

```text
Start key = 1000

For each character in username:
    key += ASCII(character) * 7

key = key XOR 0x1234
return key
```

### Example: `carter`

For `carter`, the character contributions are:

| Character | ASCII | × 7 |
|---|---:|---:|
| `c` | 99 | 693 |
| `a` | 97 | 679 |
| `r` | 114 | 798 |
| `t` | 116 | 812 |
| `e` | 101 | 707 |
| `r` | 114 | 798 |

```text
1000 + 693 + 679 + 798 + 812 + 707 + 798 = 5487
5487 XOR 0x1234 = 1883
```

Therefore, the generated key for `carter` is **1883**, which was accepted by the original validator.

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

<img width="978" height="558" alt="Screenshot 2026-09-15 154421" src="https://github.com/user-attachments/assets/2f1aeade-3646-490d-8e27-80f2d1a0232a" />

**Figure 5.** Error paths for unreadable username or invalid numeric input, along with the common exit block.

The program also contains cleanup/input-handling logic before exiting.

<img width="1001" height="550" alt="Screenshot 2026-09-15 154411" src="https://github.com/user-attachments/assets/11d1ce32-f26e-4876-8ec3-431abd312423" />

**Figure 6.** Final input cleanup and exit logic used after validation.

---

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

## Translating `calculateKey` Directly into Python

The Python code follows the assembly almost line-for-line at the algorithm level:

```text
Assembly: mov [rbp+var_4], 3E8h
Python:   key = 1000

Assembly: read one byte from the username
Python:   for character in username

Assembly: shl eax, 3 / sub eax, edx
Python:   ord(character) * 7

Assembly: add [rbp+var_4], eax
Python:   key += ord(character) * 7

Assembly: xor eax, 1234h
Python:   key ^= 0x1234
```

This means the keygen is reproducing the validator's calculation rather than bypassing its comparison.


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

The Python code directly recreates `calculateKey`: `ord()` gets each character's numeric value, the value is multiplied by 7 and added to a starting value of 1000, and the completed value is XORed with `0x1234`. The decimal result is printed for use in the original validator. The validator executable is not modified.

---

# 5. Demonstrate Success

I tested the reconstructed Python key generator with three different usernames and then entered each generated decimal key into the original, unmodified `license_check_student.exe`. All three username/key combinations were accepted by the validator.

The Python keygen was also run directly in Spyder. The screenshot below shows the source code and generated output for two of the test usernames.

<img width="1818" height="1062" alt="Screenshot 2026-09-15 160139" src="https://github.com/user-attachments/assets/01255d5d-e74f-4c73-8977-761a529b67b2" />

**Figure 7.** Python replacement key generator running in Spyder. It generated `252` for `ducky` and `1883` for `carter`.

## Verification Test 1 - `ducky`

```text
Username: ducky
Generated Key: 252
Validator Result: License accepted!
```

<img width="1056" height="553" alt="Screenshot 2026-09-15 160051" src="https://github.com/user-attachments/assets/f787db7d-56e5-4cc5-8f86-7909cdc84549" />

**Figure 8.** The original validator accepts username `ducky` with the generated decimal key `252`.

## Verification Test 2 - `carter`

```text
Username: carter
Generated Key: 1883
Validator Result: License accepted!
```

<img width="1053" height="557" alt="Screenshot 2026-09-15 160129" src="https://github.com/user-attachments/assets/84cb4fdb-c9a1-4f28-b914-bd84f7c70de7" />

**Figure 9.** The original validator accepts username `carter` with the generated decimal key `1883`.

## Verification Test 3 - `hello`

```text
Username: hello
Generated Key: 64
Validator Result: License accepted!
```

<img width="1058" height="563" alt="Screenshot 2026-09-15 160204" src="https://github.com/user-attachments/assets/1761c438-8ba2-4b00-9965-bfee91ab4efd" />

**Figure 10.** The original validator accepts username `hello` with the generated decimal key `64`.

These three successful tests demonstrate that the recovered algorithm is correct. The key generator is not limited to one hard-coded username or key; it reproduces the same calculation performed by the original validator.

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

