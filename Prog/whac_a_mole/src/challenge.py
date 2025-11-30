#! /usr/local/bin/python

import cv2
import random
import base64
from io import BytesIO
from PIL import Image
import signal
import sys

ROUNDS = 15
BACKGROUND_IMG = "resources/lawn.png"
MOLE_IMG = "resources/mole.png"
FLAG = "Hero{c0l0r_m4sk1ng_4_c1u5t3r1ng_30cbdb51ae9a289fadcaa7be2f534151}"

def generate_ctf_image(background_path, element_path, num_elements, padding, element_scale, max_attempts):
    # Load images
    bg = cv2.imread(background_path, cv2.IMREAD_COLOR)
    elem = cv2.imread(element_path, cv2.IMREAD_UNCHANGED)

    bg_h, bg_w = bg.shape[:2]

    # Resize element based on background size
    target_size = int(min(bg_w, bg_h) * element_scale)
    scale_factor = target_size / max(elem.shape[:2])
    new_w = int(elem.shape[1] * scale_factor)
    new_h = int(elem.shape[0] * scale_factor)
    elem = cv2.resize(elem, (new_w, new_h), interpolation=cv2.INTER_AREA)

    elem_h, elem_w = elem.shape[:2]
    placed_boxes = []

    def intersects(x, y, w, h):
        for (px, py, pw, ph) in placed_boxes:
            if not (x + w + padding < px or x > px + pw + padding or
                    y + h + padding < py or y > py + ph + padding):
                return True
        return False

    # Place elements
    nb_elements = 0
    for _ in range(num_elements):
        for _ in range(max_attempts):
            x = random.randint(0, bg_w - elem_w - 1)
            y = random.randint(0, bg_h - elem_h - 1)

            if not intersects(x, y, elem_w, elem_h):
                nb_elements += 1
                placed_boxes.append((x, y, elem_w, elem_h))

                if elem.shape[2] == 4:
                    alpha = elem[:, :, 3] / 255.0
                    for c in range(3):
                        bg[y:y+elem_h, x:x+elem_w, c] = (
                            alpha * elem[:, :, c] +
                            (1 - alpha) * bg[y:y+elem_h, x:x+elem_w, c]
                        )
                else:
                    bg[y:y+elem_h, x:x+elem_w] = elem

                break

    # Convert to Base64
    pil_img = Image.fromarray(cv2.cvtColor(bg, cv2.COLOR_BGR2RGB))
    buffered = BytesIO()
    pil_img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return img_str, nb_elements

def timeout_handler(signum, frame):
    print("\n[!] Timeout: you took too long (2s).")
    sys.exit(1)

# Register the signal handler
signal.signal(signal.SIGALRM, timeout_handler)

def main():
    banner()
    for i in range(ROUNDS):
        n = random.randint(3, min(max(i,5), 12))

        print("IMAGE:")
        b64img, nb_elements = generate_ctf_image(BACKGROUND_IMG, MOLE_IMG, n, 4, 1.0 / (n * 0.7), 500)
        print(b64img)
        
        print("How many moles ?")
        try:
            signal.alarm(2)  # set 2s timeout
            answer = int(input(">> ").strip())
            signal.alarm(0)  # cancel alarm if answered in time
        except ValueError:
            print("[!] Error: you must submit integers only")
            sys.exit(1)
        except Exception:
            print("[!] Error: too slow...")
            sys.exit(1)

        if answer != nb_elements:
            print(f"[x] Wrong answer! There were {nb_elements} moles...")
            sys.exit(1)

    print(FLAG)

def banner():
    print("  (`\ .-') /` ('-. .-.   ('-.                        ('-.           _   .-')                             ('-.   ")
    print("   `.( OO ),'( OO )  /  ( OO ).-.                   ( OO ).-.      ( '.( OO )_                         _(  OO)  ")
    print(",--./  .--.  ,--. ,--.  / . --. /   .-----.         / . --. /       ,--.   ,--.).-'),-----.  ,--.     (,------. ")
    print("|      |  |  |  | |  |  | \-.  \   '  .--./         | \-.  \        |   `.'   |( OO'  .-.  ' |  |.-')  |  .---' ")
    print("|  |   |  |, |   .|  |.-'-'  |  |  |  |('-.       .-'-'  |  |       |         |/   |  | |  | |  | OO ) |  |     ")
    print("|  |.'.|  |_)|       | \| |_.'  | /_) |OO  )       \| |_.'  |       |  |'.'|  |\_) |  |\|  | |  |`-' |(|  '--.  ")
    print("|         |  |  .-.  |  |  .-.  | ||  |`-'|         |  .-.  |       |  |   |  |  \ |  | |  |(|  '---.' |  .--'  ")
    print("|   ,'.   |  |  | |  |  |  | |  |(_'  '--'\         |  | |  |       |  |   |  |   `'  '-'  ' |      |  |  `---. ")
    print("'--'   '--'  `--' `--'  `--' `--'   `-----'         `--' `--'       `--'   `--'     `-----'  `------'  `------' ")

if __name__ == "__main__":
    main()

