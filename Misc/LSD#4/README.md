# LSD#4

### Category 

Misc

### Difficulty

Medium

### Tags

- steganography
- lsb

### Author

Thib

### Description

Babe wakup, LSD#4 is out now!

Don't try to throw random tools at this poor image. Go back to the basics and learn the detection techniques.

Good luck!

(Little hint : The square measures 100x100 and starts at coordinates 1000:1000)

### Files

- [secret.png](secret.png)

### Write up

This challenge is similar to last year's.

In order to solve this challenge, it is enough to look at the title to give us an interesting lead: the LSD (Least-Significant Bit).
The description tells us that it is useless to launch automatic scripts and that we have to think about it, too bad.

There is a fairly simple way to detect traces of LSB in an image. 

Some basics before going further. A colour image is made up of pixels. Each pixel is composed of three RGB layers for Red Green Blue. 
In computing, each of the three layers is a value between 0 and 255. 

![Pixels](write-up/pixels.jpg)

Thus, to have a red pixel, the pixel must have the value (255,0,0) which could be translated as 100% red, 0% green and 0% blue. Yellow is a mixture of red and green. A yellow pixel will therefore have a value of (255,255,0) which is translated as : 100% red, 100% green and 0% blue.

We also know that in computing, everything is binary. So a red pixel is coded like this: 

```
R : (11111111)
G : (00000000)
B : (00000000)
```

What happens if we set the Least Significant Bit to 0 on the Red layer? 

Color with red value at 255 :
![Pixel full red](write-up/FullRed.png)

Color with red value at 254 :
![Pixel with LSB at 0](write-up/LSBRed.png)

The two colours are different but to the naked eye the two colours look identical. This is the principle on which the technique is based, we will hide our message in the least significant bits of an image. 

Now that we know how it works, let's look at how we can detect it. The aim is to make this normally invisible change much more visible to the naked eye. Filters exist to do exactly what we want. These filters will display the image according to the value of each of the 8 bits of each layer. 

Usully, I use [AperiSolve](https://www.aperisolve.com/) which allows me to display the image according to the 16 filters displayed, but this time it was not available so I stole a part of their source code and put it in `decomposer.py`.

Each of these images will keep one of the 8 bits of the red layer while setting all others to 0. 

The first filter on the red layer : 

![](images_decompo/Red_bit_0.png)


We realise that a strange rectangle appears, just as if the least significant bits were not all the same on the red layer... 

The challenge description says that the coordinates of the rectangle's starting point are (1000:1000) and that the rectangle is 100x100. You must therefore iterate over all pixels and retrieve the value of the last pixel in the red panel.


```python
START_X = 1000
START_Y = 1000
RECT_WIDTH = 100
RECT_HEIGHT = 100

def stringToFile(string, dst):
    file = open(dst, 'w', encoding='utf-8')
    file.write(string)
    file.close()

def binaryToString(binary):
    return ''.join([chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)])

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

```

### Flag

Hero{M4YB3_TH3_L4ST_LSB?}
