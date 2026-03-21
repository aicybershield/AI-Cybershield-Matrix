import sys
import json
import os
import datetime
from PIL import Image, ExifTags

def extract_metadata(filepath):
    final_data = {}
    
    # --- LEVEL 1: FILE SYSTEM METADATA (Always Exists) ---
    try:
        stats = os.stat(filepath)
        final_data['File Info'] = {
            "Filename": os.path.basename(filepath),
            "Size": f"{round(stats.st_size / 1024, 2)} KB",
            "Created": datetime.datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            "Modified": datetime.datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            "Absolute Path": filepath
        }
    except Exception as e:
        final_data['File Info'] = {"Error": str(e)}

    # --- LEVEL 2: IMAGE ATTRIBUTES (Resolution, Format) ---
    try:
        img = Image.open(filepath)
        final_data['Image Attributes'] = {
            "Format": img.format,
            "Mode": img.mode,
            "Resolution": f"{img.width} x {img.height} pixels",
            "Is Animated": getattr(img, "is_animated", False),
            "Frames": getattr(img, "n_frames", 1)
        }
        
        # --- LEVEL 3: EXIF DATA (Camera, GPS - Often Stripped) ---
        exif_info = {}
        raw_exif = img._getexif()
        
        if raw_exif:
            for tag, value in raw_exif.items():
                decoded = ExifTags.TAGS.get(tag, tag)
                # Clean up binary/long data for clean JSON
                if isinstance(value, bytes):
                    value = "<Binary Data>"
                if len(str(value)) > 100:
                    value = str(value)[:100] + "..."
                exif_info[str(decoded)] = str(value)
        
        if exif_info:
            final_data['EXIF Data'] = exif_info
        else:
            final_data['EXIF Data'] = {"Status": "Not Found (Likely stripped by WhatsApp/Social Media)"}
            
    except IOError:
        final_data['Error'] = "Not a valid image file."
    except Exception as e:
        final_data['Error'] = f"Processing Error: {str(e)}"

    return {
        "ok": True,
        "tool": "Metadata Extractor",
        "risk_level": "Info",
        "main_finding": f"Extracted {len(final_data.get('EXIF Data', []))} EXIF tags and basic file info.",
        "data": final_data
    }

# --- CLI HANDLER ---
if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            # Handle file path argument
            file_path = " ".join(sys.argv[1:]).strip()
            
            # Remove quotes if present (Windows issue)
            if file_path.startswith("'") and file_path.endswith("'"): file_path = file_path[1:-1]
            if file_path.startswith('"') and file_path.endswith('"'): file_path = file_path[1:-1]
            
            if os.path.exists(file_path):
                result = extract_metadata(file_path)
                print(json.dumps(result))
            else:
                print(json.dumps({"ok": False, "error": "File not found."}))
        else:
            print(json.dumps({"ok": False, "error": "No file path provided."}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))