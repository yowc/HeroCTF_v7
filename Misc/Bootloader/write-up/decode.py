from Crypto.Cipher import AES

key = bytes([
    0x13, 0x37, 0xC0, 0xDE,
    0xBA, 0xAD, 0xF0, 0x0D,
    0x42, 0x42, 0x42, 0x42,
    0x99, 0x88, 0x77, 0x66
])

cipher_hex = "CE04188B3AA1F39921E5ABBCB0BD7531BB723B6ECA66C3FEDCA81C587E8588350C1035DA0D1C58E6868FE8E46CFC7551" 
cipher = bytes.fromhex(cipher_hex)

cipher = cipher[:48]

cipher_obj = AES.new(key, AES.MODE_ECB)
plaintext = cipher_obj.decrypt(cipher)

print(plaintext)
print(plaintext.rstrip(b"\x00").decode())
