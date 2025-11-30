import base64
import cv2
import numpy as np
from PIL import Image
from io import BytesIO
from pwn import *

def count_moles(b64img):
    # Decode base64 → NumPy image
    img_bytes = base64.b64decode(b64img)
    img = Image.open(BytesIO(img_bytes)).convert("RGB")
    img_np = np.array(img)
    img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)

    # Convert to HSV
    hsv = cv2.cvtColor(img_cv, cv2.COLOR_BGR2HSV)

    # Define color for the dirt
    lower_brown = np.array([5, 50, 50])
    upper_brown = np.array([25, 255, 200])

    # Mask for the color range
    mask = cv2.inRange(hsv, lower_brown, upper_brown)
    # HERE: we could add a 2nd mask and use cv2.bitwise_or to merge them together,
    # if we wanter to detect the grey part of the mole as well, not just the dirt.
    # Usefull in more complexe images.

    # Stats will contain the bounding box of each connected blob
    _, _, stats, _ = cv2.connectedComponentsWithStats(mask)

    # Filter small blobs (to avoid noise)
    filtered_stats = [stat for stat in stats[1:] if stat[cv2.CC_STAT_AREA] > 200]
    count = len(filtered_stats)

    return count


# Adjust depending challenge adress
HOST = "localhost"
PORT = 8001

io = remote(HOST, PORT)

while True:
    line = io.recvline()
    if b"IMAGE:" in line:
        # Read the base64 encoded image
        b64img = io.recvline().strip()
        log.info(f"Got image (length {len(b64img)})")

        # The server asks for answer
        io.recvuntil(b">> ")

        answer = count_moles(b64img)

        # Send back the answer
        io.sendline(str(answer).encode())

    elif b"Wrong answer!" in line or b"Hero" in line:
        # Print the line and exit if it's an error or contains the flag
        print(line.decode().strip())
        io.close()
        break
    else:
        log.info(line.decode().strip())