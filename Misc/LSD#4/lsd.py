from PIL import Image
import numpy as np
from math import *
import os

START_X = 1000
START_Y = 1000
RECT_WIDTH = 100
RECT_HEIGHT = 100

def stringToBinary(string):
    return ''.join([format(ord(i), "08b") for i in string])

def fileToString(file_src):
    fileContent = ""
    if not os.path.exists(file_src):
        print("[-] ERROR: File not found")
        exit()
    file = open(file_src, 'r', encoding='utf-8')
    while 1:
        char = file.read(1)          
        if not char:
            break  
        fileContent = fileContent + char
    file.close()
    return fileContent

def stringToFile(string, dst):
    file = open(dst, 'w', encoding='utf-8')
    file.write(string)
    file.close()

def binaryToString(binary):
    return ''.join([chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)])

def encode(image_src, message_src):
    print("[-] Encoding... ")
    if not os.path.exists(image_src):
        print("[-] ERROR: Image not found")
        exit()

    img = Image.open(image_src, 'r')
    img = img.convert("RGB")
    width, height = img.size

    if width < (START_X + RECT_WIDTH) or height < (START_Y + RECT_HEIGHT):
        print("[-] ERROR : Image is too small for this hiding spot coordinates.")
        exit()

    data = fileToString(message_src)
    data += chr(0)

    print("[-] Message file opened !")

    maximumSizeMessage = RECT_WIDTH * RECT_HEIGHT
    print("[-] Maximum size of message: {} bits".format(maximumSizeMessage))

    bits_message = stringToBinary(data)
    print("[-] Message size in bits: {} bits".format(len(bits_message)))

    if len(bits_message) > maximumSizeMessage:
        print("[-] ERROR : Message is too big to be hide in the image :(")
        exit()
    else:
        print("[-] There is enough space to hide the message !")
    
    i = 0
    print(f"[-] Hiding in RED channel at ({START_X},{START_Y})...")

    for y in range(START_Y, START_Y + RECT_HEIGHT):
        for x in range(START_X, START_X + RECT_WIDTH):
            
            pixel = list(img.getpixel((x, y)))
            
            if (i < len(bits_message)):
                pixel[0] = pixel[0] & ~1 | int(bits_message[i])
                i = i + 1
                img.putpixel((x, y), tuple(pixel))
            else:
                break
        if i >= len(bits_message):
            break

    print("[-] Message encoded !")
    print("[-] Saving image...")
    img.save("secret.png", "PNG")
    print("[-] Done ! Image saved as secret.png")

def decode(src):
    print("[-] Decoding... ")
    if not os.path.exists(src):
        print("[-] ERROR: Image not found")
        exit()
    
    img = Image.open(src, 'r')
    extracted_bin = ""
    current_byte = ""
    found_terminator = False

    print(f"[-] Reading Red channel at ({START_X},{START_Y})...")

    for y in range(START_Y, START_Y + RECT_HEIGHT):
        for x in range(START_X, START_X + RECT_WIDTH):
            
            pixel = list(img.getpixel((x, y)))
            
            bit = str(pixel[0] & 1)
            current_byte += bit

            if len(current_byte) == 8:
                if current_byte == "00000000":
                    found_terminator = True
                    break
                
                extracted_bin += current_byte
                current_byte = ""
        
        if found_terminator:
            break
    
    stringToFile(binaryToString(extracted_bin), "extracted.txt")
    print("[-] Message extracted !")
    print("[-] Message saved as extracted.txt")


print("##########################################################")
print("######################## ENCODING ########################")
print("##########################################################")
encode('LSD.png','message.txt')
print("")

print("##########################################################")
print("######################## DECODING ########################")
print("##########################################################")
decode('secret.png')