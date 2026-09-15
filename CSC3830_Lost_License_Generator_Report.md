
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


# 2. Trace the Calculation - Detailed Analysis of `calculateKey`

After locating the call to `calculateKey` in `main`, I opened that function directly in IDA. This is the most important function in the challenge because it contains the complete algorithm used to derive the expected license key from the username.

![Figure 4 - calculateKey function](13ff04d7-2e99-4abe-a502-2fbf589ae74e.png)

**Figure 4.** Complete `calculateKey` control-flow graph. The function initializes a value, loops through the username one byte at a time, performs arithmetic on each character, and applies a final XOR before returning.

## Step 1 - Receive the Username Pointer

The function begins with:

```asm
push    rbp
mov     rbp, rsp
sub     rsp, 10h
mov     [rbp+arg_0], rcx
```

On 64-bit Windows, `RCX` is used for the first function argument. In this case, `main` previously placed the address of the username into `RCX` before calling `calculateKey`.

Therefore:

```text
arg_0 = pointer to the first character of username
```

The function stores this pointer on the stack so it can repeatedly access and advance through the string.

## Step 2 - Initialize the Running Key

The next important instruction is:

```asm
mov     [rbp+var_4], 3E8h
```

`0x3E8` is `1000` in decimal.

Therefore:

```text
key = 1000
```

`var_4` is the running key value used throughout the loop.

## Step 3 - Check the Current Character

Execution jumps to the loop condition:

```asm
loc_14000147E:
mov     rax, [rbp+arg_0]
movzx   eax, byte ptr [rax]
test    al, al
jnz     short loc_140001465
```

The instructions work as follows:

```asm
mov rax, [rbp+arg_0]
```

loads the current username pointer.

```asm
movzx eax, byte ptr [rax]
```

reads one byte from that address. This is the current character.

For example, if the username is:

```text
carter
```

the first iteration reads:

```text
'c' = ASCII 99
```

The instruction:

```asm
test al, al
```

checks whether the character is zero. C strings end with a null byte (`0x00`), so this is effectively checking:

```text
Is the current character '\0'?
```

Then:

```asm
jnz short loc_140001465
```

jumps to the calculation block if the character is **not zero**.

This creates the equivalent of:

```c
while (*username != '\0')
```

## Step 4 - Load the Character's Numeric Value

Inside the loop:

```asm
mov     rax, [rbp+arg_0]
movzx   eax, byte ptr [rax]
movzx   edx, al
mov     eax, edx
```

The character is loaded again and zero-extended so its unsigned byte value can be used in arithmetic.

Conceptually:

```text
characterValue = ASCII(current character)
EAX = characterValue
EDX = characterValue
```

For lowercase `c`:

```text
characterValue = 99
EAX = 99
EDX = 99
```

## Step 5 - Multiply the Character by 7

The program does not contain a normal `imul ..., 7` instruction. Instead it performs:

```asm
shl     eax, 3
sub     eax, edx
```

`shl eax, 3` shifts the value left three bits:

```text
EAX = characterValue * 8
```

Then:

```asm
sub eax, edx
```

subtracts the original character value:

```text
EAX = (characterValue * 8) - characterValue
```

which simplifies to:

```text
EAX = characterValue * 7
```

For `c`:

```text
ASCII('c') = 99

99 * 8 = 792
792 - 99 = 693

Therefore:
99 * 7 = 693
```

This is one of the most important pieces of the recovered algorithm.

## Step 6 - Add the Character Contribution to the Key

The next instruction is:

```asm
add     [rbp+var_4], eax
```

Since `var_4` is the running key:

```text
key = key + (ASCII(character) * 7)
```

For the first character of `carter`:

```text
Starting key = 1000
'c' = 99
99 * 7 = 693

key = 1000 + 693
key = 1693
```

## Step 7 - Advance to the Next Character

The loop then executes:

```asm
add     [rbp+arg_0], 1
```

Because each username character is one byte, adding `1` to the pointer moves it to the next character.

For:

```text
carter
^
```

after the increment:

```text
carter
 ^
```

The blue control-flow arrow returns to `loc_14000147E`, where the next character is checked.

The process repeats for every character:

```text
Read character
      |
      v
Is character 0?
  |         |
 NO        YES
  |         |
  v         |
ASCII value |
  |         |
  v         |
value * 8   |
  |         |
  v         |
subtract original value
  |
  v
value * 7
  |
  v
add to key
  |
  v
pointer + 1
  |
  +----------> loop back
```

## Step 8 - Exit the Loop

Eventually the pointer reaches the null terminator at the end of the username.

At that point:

```asm
test al, al
```

finds a zero value, so:

```asm
jnz short loc_140001465
```

is **not taken**.

Execution falls through to the return block.

## Step 9 - Apply the Final XOR

The final calculation is:

```asm
mov     eax, [rbp+var_4]
xor     eax, 1234h
```

First, the accumulated key is copied into `EAX`.

Then it is XORed with:

```text
0x1234
```

Therefore:

```text
finalKey = accumulatedKey XOR 0x1234
```

The function then executes:

```asm
add     rsp, 10h
pop     rbp
retn
```

and returns the final value in `EAX`.

## Complete `calculateKey` Process

The entire function can therefore be represented as:

```text
calculateKey(username)
        |
        v
key = 1000
        |
        v
Read current character <-------------------+
        |                                   |
        v                                   |
Is character '\0'?                          |
   |              |                         |
  YES             NO                        |
   |              |                         |
   |              v                         |
   |       Get ASCII value                  |
   |              |                         |
   |              v                         |
   |        Multiply by 8                   |
   |              |                         |
   |              v                         |
   |       Subtract original                |
   |              |                         |
   |              v                         |
   |        Character * 7                   |
   |              |                         |
   |              v                         |
   |          Add to key                    |
   |              |                         |
   |              v                         |
   |       Move pointer + 1 ----------------+
   |
   v
key XOR 0x1234
   |
   v
Return key in EAX
```

## Example - Manually Calculating the Key for `carter`

The successful test used:

```text
username = carter
```

The character values are:

| Character | ASCII | ASCII × 7 |
|---|---:|---:|
| `c` | 99 | 693 |
| `a` | 97 | 679 |
| `r` | 114 | 798 |
| `t` | 116 | 812 |
| `e` | 101 | 707 |
| `r` | 114 | 798 |

Starting with 1000:

```text
1000 + 693 = 1693
1693 + 679 = 2372
2372 + 798 = 3170
3170 + 812 = 3982
3982 + 707 = 4689
4689 + 798 = 5487
```

The accumulated value is therefore:

```text
5487
```

The final step is:

```text
5487 XOR 0x1234 = 1883
```

So:

```text
calculateKey("carter") = 1883
```

This matches the successful validator test.

## Example - `ducky`

| Character | ASCII | ASCII × 7 |
|---|---:|---:|
| `d` | 100 | 700 |
| `u` | 117 | 819 |
| `c` | 99 | 693 |
| `k` | 107 | 749 |
| `y` | 121 | 847 |

```text
key = 1000
key = 1000 + 700 + 819 + 693 + 749 + 847
key = 4808

4808 XOR 0x1234 = 252
```

Therefore:

```text
calculateKey("ducky") = 252
```

## Example - `hello`

| Character | ASCII | ASCII × 7 |
|---|---:|---:|
| `h` | 104 | 728 |
| `e` | 101 | 707 |
| `l` | 108 | 756 |
| `l` | 108 | 756 |
| `o` | 111 | 777 |

```text
key = 1000
key = 1000 + 728 + 707 + 756 + 756 + 777
key = 4724

4724 XOR 0x1234 = 64
```

Therefore:

```text
calculateKey("hello") = 64
```

These manually calculated values match the keys accepted by the original executable.

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

1. `key` starts at `1000`.
2. Python's `ord()` function gets the numeric character value.
3. Each character value is multiplied by `7`.
4. The result is added to the running key.
5. After the username is processed, the key is XORed with `0x1234`.
6. The final value is printed in decimal because the original validator expects a decimal key.

The keygen does not modify `license_check_student.exe`.

---

# 5. Demonstrate Success

I tested the reconstructed Python key generator with three different usernames and then entered each generated decimal key into the original, unmodified `license_check_student.exe`. All three username/key combinations were accepted by the validator.

The Python keygen was also run directly in Spyder. The screenshot below shows the source code and generated output for two of the test usernames.

![Figure 7 - Python keygen source and generated keys](keygen_source_and_output.png)

**Figure 7.** Python replacement key generator running in Spyder. It generated `252` for `ducky` and `1883` for `carter`.

## Verification Test 1 - `ducky`

```text
Username: ducky
Generated Key: 252
Validator Result: License accepted!
```

![Figure 8 - ducky accepted with key 252](verification_ducky.png)

**Figure 8.** The original validator accepts username `ducky` with the generated decimal key `252`.

## Verification Test 2 - `carter`

```text
Username: carter
Generated Key: 1883
Validator Result: License accepted!
```

![Figure 9 - carter accepted with key 1883](verification_carter.png)

**Figure 9.** The original validator accepts username `carter` with the generated decimal key `1883`.

## Verification Test 3 - `hello`

```text
Username: hello
Generated Key: 64
Validator Result: License accepted!
```

![Figure 10 - hello accepted with key 64](verification_hello.png)

**Figure 10.** The original validator accepts username `hello` with the generated decimal key `64`.

These three successful tests demonstrate that the recovered algorithm is correct. The key generator is not limited to one hard-coded username or key; it reproduces the same calculation performed by the original validator.

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
| Three successful verification screenshots | Yes |

