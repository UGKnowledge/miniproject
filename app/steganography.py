from PIL import Image

def encode_message(image_path, message):
    # Open the image
    img = Image.open(image_path)
    encoded = img.copy()
    width, height = img.size
    
    # Add a delimiter to the message to indicate the end
    message += "###"
    message_bin = ''.join([format(ord(char), "08b") for char in message])
    
    message_idx = 0
    
    # Iterate over each pixel in the image
    for row in range(height):
        for col in range(width):
            pixel = list(img.getpixel((col, row)))
            for n in range(3):  # RGB channels
                if message_idx < len(message_bin):
                    # Modify the least significant bit (LSB)
                    pixel[n] = pixel[n] & ~1 | int(message_bin[message_idx])
                    message_idx += 1
            encoded.putpixel((col, row), tuple(pixel))
            if message_idx >= len(message_bin):
                break
        if message_idx >= len(message_bin):
            break
    
    # Return the encoded image
    return encoded


def decode_message(image_path):
    img = Image.open(image_path)
    binary_data = ""
    
    # Iterate over each pixel in the image
    for row in range(img.height):
        for col in range(img.width):
            pixel = img.getpixel((col, row))
            for n in range(3):  # RGB channels
                # Extract the least significant bit (LSB)
                binary_data += str(pixel[n] & 1)
    
    # Split binary data into 8-bit chunks
    all_bytes = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
    
    # Convert from binary to string
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-3:] == "###":
            break
    
    return decoded_data[:-3]  # Remove the delimiter
