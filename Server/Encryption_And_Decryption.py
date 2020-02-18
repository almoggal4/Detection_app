# every key encrypts the data differently, therefore only the key holder\s can decrypt it. This algorithm uses ASCII
# and it's non possible to know what the value of real high numbers in ASCII is. So the code uses that only if you know
# a certain number(the key) you can encrypt\decrypt the messages, and you can't do this without the key because you
# can't know the values of the encrypted data. Therefore the data and the keys is only known by the server and no one
# code break algorithm.


def encryption(data, encrypt_key=100):  # encrypt key < 160,000
    encode_data = []
    for string1 in data:
        dec_numbers = ["encoded"]
        encoded_str = ""
        for ch in string1:
            counter = 0
            if type(ch) == int or not ch.isascii():
                dec_numbers.append(ch)
                dec_numbers.append(counter)
            else:
                dec = str(ord(ch))
                if int(dec) % 10 != 0:
                    counter = 40
                    dec = int(dec[::-1])
                    while dec > 255:
                        dec = dec - 100
                        counter = counter + encrypt_key
                dec_numbers.append(int(dec))
                dec_numbers.append(counter)
        for ch in dec_numbers[1:]:
            if type(ch) == str:
                encoded_str = encoded_str + ch
            else:
                encoded_str = encoded_str + chr(ch)
        encode_data.append(encoded_str)
    return encode_data


# decryption all the data the client sent. (key)
def decryption(data, decrypy_key=100):  # decrypt key < 160,000
    # print(data)
    decode_data = []
    for string in data:
        even = 0
        dec_numbers = []
        for ch in string:
            try:
                dec_numbers.append(ord(ch))
            except:
                dec_numbers.append(ch)

        dec_numbers_decode = []
        decode_string = ""
        while even != len(dec_numbers):
            if even % 2 == 0:
                if (dec_numbers[even+1]) == 0:
                    dec_number = dec_numbers[even]
                else:
                    div = int((dec_numbers[even+1] - 40)/decrypy_key) * 100
                    dec_number = int(str((dec_numbers[even] + div))[::-1])
                dec_numbers_decode.append(dec_number)
            even = even + 1
        for ch in dec_numbers_decode:
            decode_string = decode_string + chr(ch)
        decode_data.append(decode_string)
    return decode_data


if __name__ == '__main__':
    msg = ['request', 'login_to_account', 'almog', 'gal1']
    enc = encryption(msg, 100)
    dec = decryption(enc, 53037)
    print(dec)
