# app.py
import os
import io
import struct
import wave
from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
from PIL import Image

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# ====================== IMAGE STEGANOGRAPHY ======================
def embed_image_data(image_bytes: bytes, secret: str) -> io.BytesIO:
    img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    width, height = img.size
    pixels = img.load()

    binary = ''.join(format(ord(c), '08b') for c in secret)
    binary += '1111111111111110'  # EOF marker

    if len(binary) > width * height * 3:
        raise ValueError("Secret message too long for this image.")

    bit_idx = 0
    for y in range(height):
        for x in range(width):
            if bit_idx >= len(binary):
                break
            r, g, b = pixels[x, y]

            if bit_idx < len(binary):
                r = (r & 0xFE) | int(binary[bit_idx])
                bit_idx += 1
            if bit_idx < len(binary):
                g = (g & 0xFE) | int(binary[bit_idx])
                bit_idx += 1
            if bit_idx < len(binary):
                b = (b & 0xFE) | int(binary[bit_idx])
                bit_idx += 1

            pixels[x, y] = (r, g, b)
        if bit_idx >= len(binary):
            break

    output = io.BytesIO()
    img.save(output, format='PNG')
    output.seek(0)
    return output


def extract_image_data(image_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    width, height = img.size
    pixels = img.load()

    binary = ''
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary += str(r & 1)
            binary += str(g & 1)
            binary += str(b & 1)

    eof = '1111111111111110'
    if eof in binary:
        binary = binary[:binary.index(eof)]

    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        if len(byte) == 8:
            text += chr(int(byte, 2))
    return text


# ====================== AUDIO STEGANOGRAPHY (MONO 16-BIT WAV) ======================
def embed_audio_data(audio_bytes: bytes, secret: str) -> io.BytesIO:
    with wave.open(io.BytesIO(audio_bytes), 'rb') as wf:
        if wf.getnchannels() != 1 or wf.getsampwidth() != 2:
            raise ValueError("Only mono 16-bit WAV files supported.")
        params = wf.getparams()
        frames = wf.readframes(params.nframes)

    num_samples = len(frames) // 2
    samples = struct.unpack('<' + 'h' * num_samples, frames)

    binary = ''.join(format(ord(c), '08b') for c in secret) + '1111111111111110'

    if len(binary) > num_samples:
        raise ValueError("Secret message too long for this audio.")

    new_samples = []
    for i in range(num_samples):
        if i < len(binary):
            bit = int(binary[i])
            new_sample = (samples[i] & ~1) | bit
            new_samples.append(new_sample)
        else:
            new_samples.append(samples[i])

    new_frames = struct.pack('<' + 'h' * len(new_samples), *new_samples)

    output = io.BytesIO()
    with wave.open(output, 'wb') as wf_out:
        wf_out.setparams(params)
        wf_out.writeframes(new_frames)
    output.seek(0)
    return output


def extract_audio_data(audio_bytes: bytes) -> str:
    with wave.open(io.BytesIO(audio_bytes), 'rb') as wf:
        if wf.getnchannels() != 1 or wf.getsampwidth() != 2:
            raise ValueError("Only mono 16-bit WAV files supported.")
        frames = wf.readframes(wf.getnframes())

    num_samples = len(frames) // 2
    samples = struct.unpack('<' + 'h' * num_samples, frames)

    binary = ''.join(str(s & 1) for s in samples)
    eof = '1111111111111110'
    if eof in binary:
        binary = binary[:binary.index(eof)]

    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        if len(byte) == 8:
            text += chr(int(byte, 2))
    return text


# ====================== FLASK ROUTES ======================
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/embed', methods=['POST'])
def embed_image_route():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    secret = request.form.get('secret', '').strip()

    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        return jsonify({"error": "Only PNG/JPG/JPEG allowed"}), 400
    if not secret:
        return jsonify({"error": "Secret text required"}), 400

    try:
        file_bytes = file.read()
        stego_io = embed_image_data(file_bytes, secret)

        original = secure_filename(file.filename)
        base = os.path.splitext(original)[0]
        download_name = f"stego_{base}.png"

        return send_file(
            stego_io,
            as_attachment=True,
            download_name=download_name,
            mimetype='image/png'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/extract', methods=['POST'])
def extract_image_route():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']

    if file.filename == '' or not file.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        return jsonify({"error": "Only PNG/JPG/JPEG allowed"}), 400

    try:
        file_bytes = file.read()
        text = extract_image_data(file_bytes)
        return jsonify({"success": True, "extracted_text": text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/audio_embed', methods=['POST'])
def embed_audio_route():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    secret = request.form.get('secret', '').strip()

    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    if not file.filename.lower().endswith('.wav'):
        return jsonify({"error": "Only .wav files allowed"}), 400
    if not secret:
        return jsonify({"error": "Secret text required"}), 400

    try:
        file_bytes = file.read()
        stego_io = embed_audio_data(file_bytes, secret)

        original = secure_filename(file.filename)
        base = os.path.splitext(original)[0]
        download_name = f"stego_{base}.wav"

        return send_file(
            stego_io,
            as_attachment=True,
            download_name=download_name,
            mimetype='audio/wav'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/audio_extract', methods=['POST'])
def extract_audio_route():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']

    if file.filename == '' or not file.filename.lower().endswith('.wav'):
        return jsonify({"error": "Only .wav files allowed"}), 400

    try:
        file_bytes = file.read()
        text = extract_audio_data(file_bytes)
        return jsonify({"success": True, "extracted_text": text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Health check for Render
@app.route('/health')
def health():
    return "OK", 200


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
