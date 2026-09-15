# -*- coding: utf-8 -*-
"""
Created on Tue Sep 15 16:00:02 2026

@author: carte
"""

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
