from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

# AES encryption and decryption
def aes_encrypt(plaintext, key):
    # Ensure the key is 16 bytes for AES-128 (AES block size is 16 bytes)
    key = key.encode('utf-8')
    key = key[:16]  # truncate or pad the key to 16 bytes (128-bit AES key)
    
    # Generate a random IV (Initialization Vector)
    cipher = AES.new(key, AES.MODE_CBC)
    
    # Pad plaintext to be a multiple of 16 bytes (AES block size)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    
    # Encrypt the data
    ciphertext = cipher.encrypt(padded_data)
    
    # The IV is prepended to the ciphertext for later decryption
    encrypted_data = base64.b64encode(cipher.iv + ciphertext).decode('utf-8')
    
    return encrypted_data

def aes_decrypt(ciphertext, key):
    key = key.encode('utf-8')
    key = key[:16]  # truncate or pad the key to 16 bytes (128-bit AES key)
    
    # Decode the base64 encoded ciphertext
    data = base64.b64decode(ciphertext)
    
    # Extract the IV from the ciphertext (first 16 bytes)
    iv = data[:16]
    
    # Extract the actual encrypted data
    ciphertext = data[16:]
    
    # Create cipher object using the same key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the data and remove padding
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    return decrypted_data.decode('utf-8')

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    method = data['method']
    plaintext = data['plaintext']
    key = data['key']
    shift = data['shift']
    response = {}

    if method == 'AES':
        response['ciphertext'] = aes_encrypt(plaintext, key)
    elif method == 'RSA':
        # RSA encryption logic (you can implement your own)
        pass
    elif method == 'Caesar':
        # Caesar encryption logic
        pass
    
    return jsonify(response)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    method = data['method']
    ciphertext = data['ciphertext']
    key = data['key']
    shift = data['shift']
    response = {}

    if method == 'AES':
        response['plaintext'] = aes_decrypt(ciphertext, key)
    elif method == 'RSA':
        # RSA decryption logic (you can implement your own)
        pass
    elif method == 'Caesar':
        # Caesar decryption logic
        pass
    
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
