xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
class AES:
    s_box = (
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )
    inv_s_box = (
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    )

    r_con = (
        0x00, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C,
        0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63,
        0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA,
        0xEF, 0xC5, 0x91, 0x39
    )

    number_of_rounds = 0

    def xor_byte_arrays(self, arr1, arr2):
        return bytearray(a ^ b for a, b in zip(arr1, arr2))

    def rot_word(self, word: bytearray):
        return bytearray([word[1], word[2], word[3], word[0]])

    def sub_word(self, word: bytearray):
        return bytearray([self.s_box[word[0]], self.s_box[word[1]], self.s_box[word[2]], self.s_box[word[3]]])

    def key_expansion(self, primary_key: bytearray):
        key_len = len(primary_key)
        word_key_len = key_len // 4
        if key_len == 16:
            #"Key length - 16 bytes"
            #"AES-128 key detected!"
            #"Number of encryption rounds - 10"
            self.number_of_rounds = 10
        elif key_len == 24:
            #"Key length - 24 bytes"
            #"AES-192 key detected!"
            #"Number of encryption rounds - 12"
            self.number_of_rounds = 12
        elif key_len == 32:
            #"Key length - 32 bytes"
            #"AES-256 key detected!"
            #"Number of encryption rounds - 14"
            self.number_of_rounds = 14
        else:
            print("Error!!!! Not correct length of key!!!!")
            return
        expanded_key = bytearray([0] * (self.number_of_rounds + 1) * 4 * 4)
        expanded_key_len = len(expanded_key)
        for i in range(key_len):
            expanded_key[i] = primary_key[i]
        for i in range(key_len, expanded_key_len, 4):
            temp = bytearray(expanded_key[i - 4:i])

            if i % key_len == 0:
                temp = self.rot_word(temp)
                temp = self.sub_word(temp)
                temp[0] ^= self.r_con[i // key_len]
            elif (word_key_len == 8) and (i % 16 == 0):
                temp = self.sub_word(temp)
            expanded_key[i:i + 4] = self.xor_byte_arrays(bytearray(expanded_key[i - key_len: i - key_len + 4]), temp)
        return expanded_key

    def sub_bytes(self, block: bytearray):
        for i in range(16):
            block[i] = self.s_box[int(block[i])]
        return block

    def inv_sub_bytes(self,  block: bytearray):
        for i in range(16):
            block[i] = self.inv_s_box[int(block[i])]
        return block

    def shift_rows(self, block: bytearray):
        # [a0  a4  a8  a12] = >     [a0  a4  a8  a12]  // 0 сдвиг
        # [a1  a5  a9  a13] = >     [a5  a9  a13 a1 ]  // 1 сдвиг
        # [a2  a6  a10 a14] = >     [a10 a14 a2  a6 ]  // 2 сдвига
        # [a3  a7  a11 a15] = >     [a15 a3  a7  a11]  // 3 сдвига
        block[1], block[5], block[9], block[13] = block[5], block[9], block[13], block[1]
        block[2], block[6], block[10], block[14] = block[10], block[14], block[2], block[6]
        block[3], block[7], block[11], block[15] = block[15], block[3], block[7], block[11]
        return block



    def inv_shift_rows(self, block: bytearray):
        block[1], block[5], block[9], block[13] = block[13], block[1], block[5], block[9]
        block[2], block[6], block[10], block[14] = block[10], block[14], block[2], block[6]
        block[3], block[7], block[11], block[15] = block[7], block[11], block[15], block[3]
        return block

    def mix_columns(self, block: bytearray):
        for i in range(4):
            block[i * 4:i * 4 + 4] = self.mix_single_column(block[i * 4:i * 4 + 4])
        return block

    def mix_single_column(self, block: bytearray):
        res = block.copy()
        res[0] = (self.g_mul(block[0], 2) ^ self.g_mul(block[1], 3) ^ self.g_mul(block[2], 1) ^ self.g_mul(block[3], 1))
        res[1] = (self.g_mul(block[0], 1) ^ self.g_mul(block[1], 2) ^ self.g_mul(block[2], 3) ^ self.g_mul(block[3], 1))
        res[2] = (self.g_mul(block[0], 1) ^ self.g_mul(block[1], 1) ^ self.g_mul(block[2], 2) ^ self.g_mul(block[3], 3))
        res[3] = (self.g_mul(block[0], 3) ^ self.g_mul(block[1], 1) ^ self.g_mul(block[2], 1) ^ self.g_mul(block[3], 2))
        return res

    def g_mul(self, a, b):
        if b == 1:
            return a
        tmp = (a << 1) & 0xff
        if b == 2:
            return tmp if a < 128 else tmp ^ 0x1b
        if b == 3:
            return self.g_mul(a, 2) ^ a

    def inv_mix_columns(self, s):
        for i in range(4):
            u = xtime(xtime(s[i*4] ^ s[i*4 + 2]))
            v = xtime(xtime(s[i*4 + 1] ^ s[i*4 + 3]))
            s[i*4] ^= u
            s[i*4 + 1] ^= v
            s[i*4 + 2] ^= u
            s[i*4 + 3] ^= v

        return self.mix_columns(s)

    def add_round_key(self, block: bytearray, round_key: bytearray):
        for i in range(16):
            block[i] = block[i] ^ round_key[i]
        return block

    def encrypt_round(self, block: bytearray, round_key: bytearray):
        block = self.sub_bytes(block)
        block = self.shift_rows(block)
        block = self.mix_columns(block)
        block = self.add_round_key(block, round_key)
        return block

    def decrypt_round(self, block: bytearray, round_key: bytearray):
        block = self.inv_shift_rows(block)
        block = self.inv_sub_bytes(block)
        block = self.add_round_key(block, round_key)
        block = self.inv_mix_columns(block)
        return block

    def encrypt_block(self, block: bytearray, full_key: bytearray):
        block = self.add_round_key(block, full_key[0:16])

        for i in range(self.number_of_rounds - 1):
            block = self.encrypt_round(block, full_key[(i + 1) * 16:(i + 1) * 16 + 16])

        block = self.sub_bytes(block)
        block = self.shift_rows(block)
        block = self.add_round_key(block, full_key[len(full_key)-16:len(full_key)])
        return block

    def decrypt_block(self,  block: bytearray, full_key: bytearray):
        block = self.add_round_key(block, full_key[len(full_key)-16:len(full_key)])
        for i in range(self.number_of_rounds - 1):
            block = self.decrypt_round(block, full_key[(self.number_of_rounds - i - 1) * 16:(self.number_of_rounds - i - 1) * 16 + 16])
        block = self.inv_shift_rows(block)
        block = self.inv_sub_bytes(block)
        block = self.add_round_key(block, full_key[0:16])
        return block

    def encrypt(self, block: bytearray, primary_key: bytearray):
        full_key = self.key_expansion(primary_key)
        block = self.encrypt_block(block, full_key)
        return block

    def decrypt(self, block: bytearray, primary_key: bytearray):
        full_key = self.key_expansion(primary_key)
        block = self.decrypt_block(block, full_key)
        return block

    def encrypt_ecb(self, data: bytearray, primary_key: bytearray):
        full_key = self.key_expansion(primary_key)
        num_of_extra_bytes = len(data) % 16
        extra_zero_bytes = bytearray([])
        if num_of_extra_bytes != 0:
            extra_zero_bytes = bytearray([0]) * (16 - num_of_extra_bytes)
        data = data + extra_zero_bytes
        encrypted_data = bytearray([])
        for i in range(15, len(data), 16):
            encrypted_data = encrypted_data + self.encrypt_block(data[i - 15: i + 1], full_key)
        return encrypted_data

    def decrypt_ecb(self,  data: bytearray, primary_key: bytearray):
        full_key = self.key_expansion(primary_key)
        decrypted_data = bytearray([])
        for i in range(15, len(data), 16):
            decrypted_data = decrypted_data + self.decrypt_block(data[i - 15: i + 1], full_key)
        return decrypted_data

    def encrypt_cbc_block(self, iv: bytearray, block: bytearray, full_key: bytearray):
        result = self.encrypt_block(self.xor_byte_arrays(block, iv), full_key)
        return result

    def encrypt_cbc(self, iv: bytearray, data: bytearray, primary_key: bytearray):
        full_key = self.key_expansion(primary_key)
        num_of_extra_bytes = len(data) % 16
        extra_zero_bytes = bytearray([])
        if num_of_extra_bytes != 0:
            extra_zero_bytes = bytearray([0]) * (16 - num_of_extra_bytes)
        data = data + extra_zero_bytes
        encrypted_data = bytearray([])
        for i in range(15, len(data), 16):
            iv = self.encrypt_cbc_block(iv, data[i - 15: i + 1], full_key)
            encrypted_data = encrypted_data + iv
        return encrypted_data

    def decrypt_cbc_block(self, iv: bytearray, block: bytearray, full_key: bytearray):
        return self.xor_byte_arrays(self.decrypt_block(block, full_key), iv)

    def decrypt_cbc(self, iv: bytearray, data: bytearray, primary_key: bytearray):
        full_key = self.key_expansion(primary_key)
        decrypted_data = bytearray([])
        for i in range(15, len(data), 16):
            decrypted_data = decrypted_data + self.decrypt_cbc_block(iv, data[i - 15: i + 1], full_key)
            iv = data[i - 15: i + 1]
        return decrypted_data


def debug_output(res: bytearray):
    str_res = ""
    for i in res:
        str_res = str_res + str(hex(int(i))) + " "
    print(str_res)


if __name__ == '__main__':
    hex_key = bytearray(
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
    input = bytearray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    aes = AES()
    res = aes.encrypt_ecb(input, hex_key)
    str_res = ""
    for i in res:
        str_res = str_res + str(hex(int(i))) + " "
    print(str_res)


    print("Test sub_bytes:")
    result = aes.sub_bytes(input)
    debug_output(result)
    result = aes.inv_sub_bytes(result)
    debug_output(result)

    print("Test shift_rows:")
    result = aes.shift_rows(input)
    debug_output(result)
    result = aes.inv_shift_rows(result)
    debug_output(result)

    print("Test mix_columns:")
    result = aes.mix_columns(input)
    debug_output(result)
    result = aes.inv_mix_columns(result)
    debug_output(result)

    print("Test decrypt:")
    result = aes.encrypt(input, hex_key)
    debug_output(result)
    result = aes.decrypt(result, hex_key)
    debug_output(result)

    print("Test decrypt_ecb:")
    result = aes.encrypt_ecb(input, hex_key)
    debug_output(result)
    result = aes.decrypt_ecb(result, hex_key)
    debug_output(result)

    print("Test decrypt_cbc:")
    result = aes.encrypt_cbc(input, input, hex_key)
    debug_output(result)
    result = aes.decrypt_cbc(input, result, hex_key)
    debug_output(result)

