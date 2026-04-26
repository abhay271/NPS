from pathlib import Path

from PIL import Image


def _bytes_to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Bit length must be a multiple of 8")

    out = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i : i + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _load_pixels(image_path: str):
    image = Image.open(image_path)
    if image.mode not in ("RGB", "RGBA"):
        image = image.convert("RGBA")

    channel_count = len(image.getbands())
    raw = image.tobytes()
    pixels = [
        tuple(raw[i : i + channel_count])
        for i in range(0, len(raw), channel_count)
    ]
    return image, pixels


def get_capacity(image_path: str) -> int:
    image, pixels = _load_pixels(image_path)
    image.close()

    total_lsb_bits = len(pixels) * 3
    total_bytes = total_lsb_bits // 8

    # Reserve 4 bytes for the big-endian payload length header.
    usable = total_bytes - 4
    return usable if usable > 0 else 0


def embed(image_path: str, data_bytes: bytes, output_path: str) -> None:
    if not isinstance(data_bytes, (bytes, bytearray)):
        raise TypeError("data_bytes must be bytes-like")

    image, pixels = _load_pixels(image_path)
    payload = len(data_bytes).to_bytes(4, "big") + bytes(data_bytes)
    payload_bits = _bytes_to_bits(payload)

    available_bits = len(pixels) * 3
    if len(payload_bits) > available_bits:
        image.close()
        raise ValueError(
            f"Image too small. Need {len(payload_bits)} bits, have {available_bits} bits."
        )

    bit_index = 0
    modified_pixels = []

    for pixel in pixels:
        channels = list(pixel)
        color_channel_count = 3

        for channel_idx in range(color_channel_count):
            if bit_index >= len(payload_bits):
                break

            channels[channel_idx] = (channels[channel_idx] & 0xFE) | payload_bits[bit_index]
            bit_index += 1

        modified_pixels.append(tuple(channels))

    stego = Image.new(image.mode, image.size)
    stego.putdata(modified_pixels)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    stego.save(output_path, format="PNG")

    image.close()
    stego.close()


def extract(image_path: str) -> bytes:
    image, pixels = _load_pixels(image_path)

    bits: list[int] = []
    for pixel in pixels:
        bits.append(pixel[0] & 1)
        bits.append(pixel[1] & 1)
        bits.append(pixel[2] & 1)

    image.close()

    if len(bits) < 32:
        raise ValueError("Stego image is too small to contain a 4-byte header")

    length_header = _bits_to_bytes(bits[:32])
    data_len = int.from_bytes(length_header, "big")

    required_data_bits = data_len * 8
    available_data_bits = len(bits) - 32
    if required_data_bits > available_data_bits:
        raise ValueError(
            f"Stego payload incomplete. Need {required_data_bits} bits, have {available_data_bits} bits."
        )

    data_bits = bits[32 : 32 + required_data_bits]
    return _bits_to_bytes(data_bits)


def get_pixel_diff(original_path: str, stego_path: str, sample_count: int = 8) -> list[dict]:
    original_image, original_pixels = _load_pixels(original_path)
    stego_image, stego_pixels = _load_pixels(stego_path)

    if original_image.size != stego_image.size:
        original_image.close()
        stego_image.close()
        raise ValueError("Original and stego images must have the same dimensions")

    diffs: list[dict] = []

    for idx, (orig_px, stego_px) in enumerate(zip(original_pixels, stego_pixels)):
        for channel_idx, channel_name in enumerate(("R", "G", "B")):
            orig_val = orig_px[channel_idx]
            stego_val = stego_px[channel_idx]

            if orig_val != stego_val:
                diffs.append(
                    {
                        "pixel_index": idx,
                        "channel": channel_name,
                        "original_bits": format(orig_val, "08b"),
                        "stego_bits": format(stego_val, "08b"),
                        "original_value": orig_val,
                        "stego_value": stego_val,
                    }
                )
                if len(diffs) >= sample_count:
                    original_image.close()
                    stego_image.close()
                    return diffs

    original_image.close()
    stego_image.close()
    return diffs


if __name__ == "__main__":
    cover_path = "images/cover.png"
    stego_path = "output/stego_test.png"
    test_message = b"Test message for LSB steganography!"

    try:
        if not Path(cover_path).exists():
            raise FileNotFoundError(
                "images/cover.png not found. Add a PNG cover image before running self-test."
            )

        Path("output").mkdir(parents=True, exist_ok=True)

        print("[1] Capacity check...")
        capacity = get_capacity(cover_path)
        if len(test_message) > capacity:
            raise ValueError(
                f"Cover image capacity is {capacity} bytes, but test message is {len(test_message)} bytes."
            )
        print(f"[PASS] Can hold {capacity} bytes")

        print("[2] Embed...")
        embed(cover_path, test_message, stego_path)
        print(f"[PASS] Embedded {len(test_message)} bytes into {stego_path}")

        print("[3] Extract...")
        recovered = extract(stego_path)
        if recovered != test_message:
            raise ValueError("Extracted message does not match embedded message")
        print(f"[PASS] Extracted: {recovered.decode('utf-8')}")

        print("[4] Pixel diff:")
        diffs = get_pixel_diff(cover_path, stego_path, sample_count=4)
        for d in diffs:
            print(
                "    Pixel {pixel}  {channel}: {orig} -> {stego}  ({ov} -> {sv})".format(
                    pixel=d["pixel_index"],
                    channel=d["channel"],
                    orig=d["original_bits"],
                    stego=d["stego_bits"],
                    ov=d["original_value"],
                    sv=d["stego_value"],
                )
            )

        print("All tests passed!")
    except Exception as exc:
        print(f"Self-test failed: {exc}")
