document.getElementById('sendButton').addEventListener('click', function() {
    console.log('Кнопка нажата!');
    const selectedOption = document.querySelector('input[name="toggle"]:checked').value;
    let uri = '/test';
    let body_data = "";
    let inputText;
    let key;
    let iv;
    let formData={}
    switch (selectedOption) {
        case 'encrypt_block':
            uri = '/encrypt_block';
            inputText = document.getElementById('input_text').value;
            key = document.getElementById('key').value;
            formData = {
                hex_data: inputText,
                hex_key: key
            };
            body_data = JSON.stringify(formData)
            break;
        case 'decrypt_block':
            uri = '/decrypt_block';
            inputText = document.getElementById('input_text').value;
            key = document.getElementById('key').value;
            formData = {
                hex_data: inputText,
                hex_key: key
            };
            body_data = JSON.stringify(formData)
            break;
        case 'key_expansion':
            uri = '/key_expansion';
            key = document.getElementById('key').value;
            formData = {
                hex_primary_key: key
            };
            body_data = JSON.stringify(formData)

            break;
        case 'encrypt':
            uri = '/encrypt';
            inputText = document.getElementById('input_text').value;
            key = document.getElementById('key').value;
            formData = {
                hex_data: inputText,
                hex_key: key
            };
            body_data = JSON.stringify(formData)
            break;
        case 'decrypt':
            uri = '/decrypt';
            inputText = document.getElementById('input_text').value;
            key = document.getElementById('key').value;
            formData = {
                hex_data: inputText,
                hex_key: key
            };
            body_data = JSON.stringify(formData)
            break;
        case 'encrypt_cbc':
            uri = '/encrypt_cbc';
            inputText = document.getElementById('input_text').value;
            key = document.getElementById('key').value;
            iv = document.getElementById('iv').value;
            formData = {
                data: inputText,
                hex_key: key,
                init_vector: iv
            };
            body_data = JSON.stringify(formData)
            break;
        case 'decrypt_cbc':
            uri = '/decrypt_cbc';
            inputText = document.getElementById('input_text').value;
            key = document.getElementById('key').value;
            iv = document.getElementById('iv').value;
            formData = {
                data: inputText,
                hex_key: key,
                init_vector: iv
            };
            body_data = JSON.stringify(formData)
            break;
        case 'encrypt_ecb':
            uri = '/encrypt_ecb';
            inputText = document.getElementById('input_text').value;
            key = document.getElementById('key').value;
            formData = {
                data: inputText,
                hex_key: key
            };
            body_data = JSON.stringify(formData)
            break;
        case 'decrypt_ecb':
            uri = '/decrypt_ecb';
            inputText = document.getElementById('input_text').value;
            key = document.getElementById('key').value;
            formData = {
                data: inputText,
                hex_key: key
            };
            body_data = JSON.stringify(formData)
            break;
    }

    console.log("URI:", uri);
    console.log("body_data:", body_data);

    fetch(uri, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: body_data
})
.then(response => {
    console.log('Статус ответа:', response.status); // Отладка
    if (response.ok) {
        return response.json();
    }
    return response.text().then(text => {
        throw new Error(`Ошибка сети: ${response.status} ${text}`);
    });
})
.then(data => {
    console.log('Успех:', data);
    document.getElementById('result').innerText = data.result;
})

});
