import os
import sys
import argparse
from PIL import Image, ImageEnhance, ImageFilter
import numpy as np
BLOCK_CHARS = {
    'quadrant_ul': '▘',  
    'quadrant_ur': '▝',  
    'quadrant_ll': '▖',  
    'quadrant_lr': '▗',  
    'upper_half': '▀',   
    'lower_half': '▄',   
    'full': '█',         
    'left_half': '▌',    
    'right_half': '▐',   
    'left_7_8': '▉',     
    'left_3_4': '▊',     
    'left_5_8': '▋',     
    'left_1_2': '▌',     
    'left_3_8': '▍',     
    'left_1_4': '▎',     
    'left_1_8': '▏',     
}
def calculate_perceived_brightness(r, g, b):
    """Calculate perceptual brightness using ITU-R BT.709 coefficients"""
    return 0.2126 * r + 0.7152 * g + 0.0722 * b
def apply_quality_enhancements(frame, enhance_level='high'):
    """
    Apply advanced image processing for terminal rendering
    """
    if enhance_level == 'none':
        return frame
    frame = frame.filter(ImageFilter.GaussianBlur(radius=0.3))
    frame = frame.filter(ImageFilter.UnsharpMask(radius=1.5, percent=120, threshold=3))
    if enhance_level == 'high':
        enhancer = ImageEnhance.Color(frame)
        frame = enhancer.enhance(1.2)
        enhancer = ImageEnhance.Contrast(frame)
        frame = enhancer.enhance(1.2)
        enhancer = ImageEnhance.Brightness(frame)
        frame = enhancer.enhance(1.05)
    elif enhance_level == 'medium':
        enhancer = ImageEnhance.Color(frame)
        frame = enhancer.enhance(1.1)
        enhancer = ImageEnhance.Contrast(frame)
        frame = enhancer.enhance(1.1)
    return frame
def gif_to_tfx(gif_path, output_path, target_width=120, target_height=32, enhance_level='high', use_dithering=False):
    """
    Convert GIF to TFX format for terminal display
    Quality features:
    - LANCZOS resampling for high-quality scaling
    - Unsharp mask filter for crisp edges
    - Color/contrast/brightness enhancement
    - Optional Floyd-Steinberg dithering for smoother gradients
    - Full 24-bit RGB color (16.7 million colors)
    - ▀ half-block characters for 2x vertical resolution
    """
    try:
        gif = Image.open(gif_path)
        frames = []
        frame_durations = []
        try:
            while True:
                frame = gif.copy()
                if frame.mode != 'RGB':
                    frame = frame.convert('RGB')
                frame = apply_quality_enhancements(frame, enhance_level)
                if use_dithering:
                    frame = frame.convert('P', palette=Image.ADAPTIVE, colors=256, dither=Image.FLOYDSTEINBERG)
                    frame = frame.convert('RGB')
                frames.append(frame)
                frame_durations.append(gif.info.get('duration', 100))
                gif.seek(gif.tell() + 1)
        except EOFError:
            pass
        print(f"Found {len(frames)} frames in GIF")
        print(f"Quality mode: {enhance_level.upper()}")
        with open(output_path, 'w', encoding='utf-8') as tfx_file:
            for frame_idx, frame in enumerate(frames):
                print(f"Processing frame {frame_idx + 1}/{len(frames)}")
                frame = resize_for_terminal(frame, target_width, target_height * 2)
                img_array = np.array(frame)
                height, width, _ = img_array.shape
                tfx_file.write('\033[H')
                for y in range(0, height - 1, 2):
                    for x in range(width):
                        top_pixel = img_array[y, x]
                        bottom_pixel = img_array[y + 1, x]
                        top_r, top_g, top_b = int(top_pixel[0]), int(top_pixel[1]), int(top_pixel[2])
                        bottom_r, bottom_g, bottom_b = int(bottom_pixel[0]), int(bottom_pixel[1]), int(bottom_pixel[2])
                        tfx_file.write(f'\033[48;2;{bottom_r};{bottom_g};{bottom_b};38;2;{top_r};{top_g};{top_b}m▀')
                    tfx_file.write('\033[0m\n')
                tfx_file.write(f'#DELAY:{frame_durations[frame_idx]}\n')
        print(f"\nTFX file created: {output_path}")
        print(f"Quality: Full 24-bit RGB, {len(frames)} frames")
        print(f"Enhancements: LANCZOS scaling, Unsharp mask, {enhance_level} quality")
        if use_dithering:
            print(f"Dithering: Floyd-Steinberg enabled")
    except Exception as e:
        print(f"Error: {e}")
        return False
    return True
def resize_for_terminal(image, target_width, target_height):
    """
    Resize image to fit terminal while maintaining aspect ratio
    Uses LANCZOS resampling for maximum quality
    """
    img_width, img_height = image.size
    aspect_ratio = img_width / img_height
    new_width = target_width
    new_height = int(target_width / aspect_ratio)
    if new_height > target_height:
        new_height = target_height
        new_width = int(target_height * aspect_ratio)
    if new_height % 2 != 0:
        new_height -= 1
    resized = image.resize((new_width, new_height), Image.LANCZOS)
    if new_width < target_width or new_height < target_height:
        background = Image.new('RGB', (target_width, target_height), (0, 0, 0))
        x_offset = (target_width - new_width) // 2
        y_offset = (target_height - new_height) // 2
        background.paste(resized, (x_offset, y_offset))
        return background
    return resized
def main():
    parser = argparse.ArgumentParser(
        description='Convert GIF to TFX format for RustNet C2 terminal (120x32)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
RustNet C2 GIF Converter - Simple and clean
Usage:
  python gif.py input.gif output.tfx              # Convert GIF to TFX
  python gif.py input.gif output.tfx --dither     # Add dithering for photos
Quality Modes:
  high (default)  - Unsharp mask, color enhancement, 24-bit RGB
  medium          - Balanced enhancements
  low             - Minimal processing
Outputs standard TFX format for 120x32 terminal using ▀ characters.
        """
    )
    parser.add_argument('input', help='Input GIF file')
    parser.add_argument('output', help='Output TFX file')
    parser.add_argument('--quality', choices=['low', 'medium', 'high'], default='high',
                       help='Quality level (default: high)')
    parser.add_argument('--dither', action='store_true',
                       help='Enable dithering for smoother gradients (use for photos)')
    args = parser.parse_args()
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found")
        sys.exit(1)
    print(f"╔══════════════════════════════════════════════════════════╗")
    print(f"║      RustNet C2 GIF Converter - 120x32 Terminal         ║")
    print(f"╚══════════════════════════════════════════════════════════╝")
    print(f"\nSettings:")
    print(f"  Terminal Size:  120x32 characters")
    print(f"  Color Depth:    24-bit RGB (16.7M colors)")
    print(f"  Quality:        {args.quality.upper()}")
    print(f"  Dithering:      {'Enabled' if args.dither else 'Disabled'}")
    print(f"  Output:         {args.output}")
    print()
    success = gif_to_tfx(args.input, args.output, 120, 32, args.quality, args.dither)
    if not success:
        sys.exit(1)
if __name__ == "__main__":
    main()
