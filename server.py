import requests
from flask import Flask, request, render_template
from AES import AES

app = Flask(__name__)


@app.route("/key_expansion",  methods=['POST'])
def key_expansion():
    json_string = request.get_json()
    hex_primary_key = json_string['hex_primary_key']
    byte_primary_key = bytearray(int(byte, 16) for byte in hex_primary_key.split())

    algorithm = AES()
    result = algorithm.key_expansion(byte_primary_key)
    hex_result = ' '.join(f'0x{byte:02x}' for byte in result)
    return {'result': hex_result}


@app.route("/encrypt_block",  methods=['POST'])
def encrypt_block():
    json_string = request.get_json()

    hex_data = json_string['hex_data']
    byte_data = bytearray(int(byte, 16) for byte in hex_data.split())

    hex_key = json_string['hex_key']
    byte_key = bytearray(int(byte, 16) for byte in hex_key.split())
    algorithm = AES()
    result = algorithm.encrypt_block(byte_data, byte_key)
    hex_result = ' '.join(f'0x{byte:02x}' for byte in result)
    return {'result': hex_result}


@app.route("/decrypt_block",  methods=['POST'])
def decrypt_block():
    json_string = request.get_json()

    hex_data = json_string['hex_data']
    byte_data = bytearray(int(byte, 16) for byte in hex_data.split())

    hex_key = json_string['hex_key']
    byte_key = bytearray(int(byte, 16) for byte in hex_key.split())
    algorithm = AES()
    result = algorithm.decrypt_block(byte_data, byte_key)
    hex_result = ' '.join(f'0x{byte:02x}' for byte in result)
    return {'result': hex_result}


@app.route("/encrypt",  methods=['POST'])
def encrypt():
    json_string = request.get_json()

    hex_data = json_string['hex_data']
    byte_data = bytearray(int(byte, 16) for byte in hex_data.split())

    hex_key = json_string['hex_key']
    byte_key = bytearray(int(byte, 16) for byte in hex_key.split())
    algorithm = AES()
    result = algorithm.encrypt(byte_data, byte_key)
    hex_result = ' '.join(f'0x{byte:02x}' for byte in result)
    return {'result': hex_result}


@app.route("/decrypt",  methods=['POST'])
def decrypt():
    json_string = request.get_json()

    hex_data = json_string['hex_data']
    byte_data = bytearray(int(byte, 16) for byte in hex_data.split())

    hex_key = json_string['hex_key']
    byte_key = bytearray(int(byte, 16) for byte in hex_key.split())
    algorithm = AES()
    result = algorithm.decrypt(byte_data, byte_key)
    hex_result = ' '.join(f'0x{byte:02x}' for byte in result)
    return {'result': hex_result}


@app.route("/encrypt_cbc",  methods=['POST'])
def encrypt_cbc():
    json_string = request.get_json()

    data = json_string['data']
    byte_data = bytearray(data, 'UTF-8')

    hex_key = json_string['hex_key']
    byte_key = bytearray(int(byte, 16) for byte in hex_key.split())

    hex_iv = json_string['init_vector']
    byte_iv = bytearray(int(byte, 16) for byte in hex_iv.split())

    algorithm = AES()
    result = algorithm.encrypt_cbc(byte_iv, byte_data, byte_key)
    hex_result = ' '.join(f'0x{byte:02x}' for byte in result)
    return {'result': hex_result}


@app.route("/decrypt_cbc", methods=['POST'])
def decrypt_cbc():
    json_string = request.get_json()

    data = json_string['data']
    byte_data = bytearray(int(byte, 16) for byte in data.split())

    hex_key = json_string['hex_key']
    byte_key = bytearray(int(byte, 16) for byte in hex_key.split())

    hex_iv = json_string['init_vector']
    byte_iv = bytearray(int(byte, 16) for byte in hex_iv.split())

    algorithm = AES()
    result = algorithm.decrypt_cbc(byte_iv, byte_data, byte_key)

    return {'result': str(result)}


@app.route("/encrypt_ecb", methods=['POST'])
def encrypt_ecb():
    json_string = request.get_json()

    data = json_string['data']
    byte_data = bytearray(data, 'UTF-8')

    hex_key = json_string['hex_key']
    byte_key = bytearray(int(byte, 16) for byte in hex_key.split())

    algorithm = AES()
    result = algorithm.encrypt_ecb(byte_data, byte_key)
    hex_result = ' '.join(f'0x{byte:02x}' for byte in result)
    return {'result': hex_result}


@app.route("/decrypt_ecb", methods=['POST'])
def decrypt_ecb():
    json_string = request.get_json()

    data = json_string['data']
    byte_data = bytearray(int(byte, 16) for byte in data.split())

    hex_key = json_string['hex_key']
    byte_key = bytearray(int(byte, 16) for byte in hex_key.split())

    algorithm = AES()
    result = algorithm.decrypt_ecb(byte_data, byte_key)
    return {'result': result.decode('UTF-8')}


@app.route("/", methods=["GET", "POST"])
def index():
    progress = "0"
    result = ""
    if request.method == "POST":
        action = request.form.get("toggle")
        input_text = request.form.get("input_text")
        key = request.form.get("key")
        iv = request.form.get("iv")
        try:
            if action == "key_expansion":
                payload = {
                 "hex_primary_key": key
                 }
            elif action == "encrypt_block":
                payload = {
                    "hex_data": input_text,
                    "hex_key": key
                }
            elif action == "decrypt_block":
                payload = {
                    "hex_data": input_text,
                    "hex_key": key
                }
            elif action == "encrypt":
                payload = {
                    "hex_data": input_text,
                    "hex_key": key
                }
            elif action == "decrypt":
                payload = {
                    "hex_data": input_text,
                    "hex_key": key
                }
            elif action == "encrypt_cbc":
                payload = {
                    "data": input_text,
                    "hex_key": key,
                    "init_vector": iv
                }
            elif action == "decrypt_cbc":
                payload = {
                    "data": input_text,
                    "hex_key": key,
                    "init_vector": iv
                }
            elif action == "encrypt_ecb":
                payload = {
                    "data": input_text,
                    "hex_key": key,
                }
            elif action == "decrypt_ecb":
                payload = {
                    "data": input_text,
                    "hex_key": key,
                }

            endpoint = action

            response = requests.post("http://127.0.0.1:5000/" + endpoint, json=payload)

            if response.status_code == 200:
                result = response.json().get("result", "Нет результата.")
                progress = 100
            else:
                result = f"Ошибка: {response.status_code} - {response.text}"

        except Exception as e:
            result = f"Ошибка: {str(e)}"

    return render_template("index.html", result=result, progress=progress)



if __name__ == "__main__":
    app.run()
