# Aperisolve was not working so i stole this form its source code

from pathlib import Path
from PIL import Image
import numpy as np
import json
import argparse

def update_data(output_dir: Path, data: dict) -> None:
    json_path = output_dir / "results.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def analyze_decomposer(input_img: Path, output_dir: Path) -> None:
    try:
        img = Image.open(input_img)
    except Exception as e:
        return

    img_np = np.array(img)

    if len(img_np.shape) == 2:
        channels = 1
    else:
        channels = img_np.shape[2]

    if channels > 1:
        full_names = ["Red", "Green", "Blue", "Alpha"]
        channel_names = full_names[:channels]
    else:
        channel_names = ["Grayscale"]

    image_json = {}

    if channels >= 3:
        superimposed_json = []
        for bit in range(8):
            bit_mask = 1 << bit
            rgb_planes = [((img_np[..., c] & bit_mask) >> bit) * 255 for c in range(3)]
            rgb_image = np.stack(rgb_planes, axis=-1).astype(np.uint8)
            rgb_img = Image.fromarray(rgb_image, mode="RGB")
            
            img_name = f"superimposed_bit_{bit}.png"
            out_path = output_dir / img_name
            
            dl_path = Path(output_dir.name) / img_name
            superimposed_json.append("/image/" + str(dl_path)) 
            
            rgb_img.save(out_path)

        image_json["Superimposed"] = superimposed_json

    for c in range(channels):
        channel_data = img_np[..., c] if channels > 1 else img_np
        channel_label = channel_names[c]
        channel_json = []
        
        for bit in range(8):
            bit_mask = 1 << bit
            bit_plane = ((channel_data & bit_mask) >> bit) * 255
            
            bit_img = Image.fromarray(bit_plane.astype(np.uint8), mode="L")
            
            img_name = f"{channel_label}_bit_{bit}.png"
            out_path = output_dir / img_name
            dl_path = Path(output_dir.name) / img_name
            
            channel_json.append("/image/" + str(dl_path))
            bit_img.save(out_path)
            
        image_json[channel_label] = channel_json

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decompose image into bit planes.")
    parser.add_argument("input_image", type=Path, help="Path to the input image.")
    parser.add_argument("output_dir", type=Path, help="Directory to save output images.")
    args = parser.parse_args()

    if not args.input_image.exists():
        print(f"[!] L'image d'entrée n'existe pas : {args.input_image}")
        exit()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    analyze_decomposer(args.input_image, args.output_dir)