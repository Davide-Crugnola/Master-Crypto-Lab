import numpy as np
from PIL import Image


class LSBSteganography:
    @staticmethod
    def encode_message(image: Image.Image, secret_bytes: bytes) -> Image.Image:
        img = image.convert("RGB")
        encoded_img = img.copy()
        length_header = len(secret_bytes).to_bytes(4, byteorder='big')
        payload = length_header + secret_bytes
        payload_bits = ''.join(format(byte, '08b') for byte in payload)

        width, height = img.size
        max_capacity = width * height * 3
        if len(payload_bits) > max_capacity:
            raise ValueError(
                f"Insufficient image capacity "
                f"({len(payload_bits)} bits required, {max_capacity} available)."
            )

        pixels = np.array(encoded_img)
        flat_pixels = pixels.flatten()

        for i, bit in enumerate(payload_bits):
            flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)

        new_pixels = flat_pixels.reshape((height, width, 3))
        return Image.fromarray(new_pixels.astype(np.uint8))

    @staticmethod
    def decode_message(image: Image.Image) -> bytes:
        img = image.convert("RGB")
        pixels = np.array(img).flatten()

        header_bits = [str(pixels[i] & 1) for i in range(32)]
        header_bytes = bytes(
            [int(''.join(header_bits[i:i + 8]), 2) for i in range(0, 32, 8)]
        )
        data_length = int.from_bytes(header_bytes, byteorder='big')

        total_bits_to_read = (4 + data_length) * 8
        if total_bits_to_read > len(pixels):
            raise ValueError("Image does not contain valid steganographic data.")

        all_bits = [str(pixels[i] & 1) for i in range(32, total_bits_to_read)]
        payload_bytes = bytes(
            [int(''.join(all_bits[i:i + 8]), 2) for i in range(0, len(all_bits), 8)]
        )
        return payload_bytes
