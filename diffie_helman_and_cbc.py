def is_prime(p):
    if p == 2 or p == 3:
        return True
    if p % 2 == 0 or p < 2:
        return False
    for i in range(3, int(p ** 0.5) + 1, 2):  # only odd numbers
        if p % i == 0:
            return False

    return True


def get_prime_factors(q):
    i = 2
    factors = []
    while i * i <= q:
        if q % i:
            i += 1
        else:
            q //= i
            factors.append(i)
    if q > 1:
        factors.append(q)
    return set(factors)


def is_generator(g, p):
    prime_factors = get_prime_factors(p - 1)
    for factor in prime_factors:
        eq = (g ** int((p - 1) / factor)) % p
        if eq == 1:
            return False

    return True


def generate_key(g, a, b, p):
    return (g ** (a * b)) % p


def str_to_binary(str):
    bin = ' '.join(format(ord(x), 'b') for x in str)
    return bin


def bin_to_str(bin):
    binary_values = bin.split()
    ascii_string = ""
    for binary_value in binary_values:
        an_integer = int(binary_value, 2)

        ascii_character = chr(an_integer)

        ascii_string += ascii_character

    return ascii_string


def encryption(iv, message, key):
    decimal_string = str_to_decimal(message)  # for xor operation
    encrypted_msg = []
    bin_enc_msg = ""
    step = 1
    for letter in decimal_string:
        print("Step: ", step)
        binary_iv = dec_to_bin(iv)
        binary_letter = dec_to_bin(letter)
        binary_key = dec_to_bin(key)
        print("IV is ", binary_iv)
        print("Letter is ", binary_letter)
        iv_xor_letter = iv ^ letter
        binary_iv_xor_letter = dec_to_bin(iv_xor_letter)
        print("IV xor letter :", binary_iv, "⊕", binary_letter, " = ", binary_iv_xor_letter)
        encrypted_letter = iv_xor_letter ^ key
        binary_enc_letter = dec_to_bin(encrypted_letter)
        print("Encrypted Letter: ", binary_iv_xor_letter, "⊕", binary_key, "=", binary_enc_letter)
        encrypted_msg.append(encrypted_letter)
        bin_enc_msg += binary_enc_letter
        iv = encrypted_letter
        print("Encrypted letter became new IV")
        print("///////////////////")
        step += 1
    print("Encrypted letter in binary: ", bin_enc_msg)
    return encrypted_msg


def decryption(iv, enc_message, key):
    decimal_message = str_to_decimal(enc_message)
    decryipted_msg = []
    bin_dec_message = ""
    step = 1
    for letter in decimal_message:
        print("Step: ", step)
        binary_iv = dec_to_bin(iv)
        binary_letter = dec_to_bin(letter)
        binary_key = dec_to_bin(key)
        print("IV is ", binary_iv)
        print("Cipher text is ", binary_letter)
        letter_xor_key = letter ^ key
        binary_letter_xor_key = dec_to_bin(letter_xor_key)
        print("Key xor cipher text :", binary_key, "⊕", binary_letter, " = ", binary_letter_xor_key)
        decrypted_letter = letter_xor_key ^ iv
        binary_dec_letter = dec_to_bin(decrypted_letter)
        print("Encrypted Letter: ", binary_letter_xor_key, "⊕", binary_iv, "=", binary_dec_letter)
        bin_dec_message += binary_dec_letter
        decryipted_msg.append(decrypted_letter)
        iv = letter
        print("Cipher Text became new IV")
        print("///////////////////")
        step += 1
    print("decrypted letter in binary: ", bin_dec_message)
    return decryipted_msg


def get_enc_dec_message_in_str(encrypt_msg):  # encrypt_msg is an array
    str_enc_msg = ""
    for encrypted_letter in encrypt_msg:
        str_encrypted_letter = dec_to_str(encrypted_letter)
        str_enc_msg += str_encrypted_letter
    return str_enc_msg


def bin_to_decimal(bin_arr):
    dec_array = []
    for bn in bin_arr:
        dec_array.append(int(bn, 2))

    return dec_array


def str_to_decimal(str):
    bin_arr = str_to_binary(str).split()
    dec_arr = bin_to_decimal(bin_arr)
    return dec_arr


def dec_to_str(dec_num):
    binary = dec_to_bin(dec_num)
    str_msg = bin_to_str(binary)
    return str_msg


def dec_to_bin(n):
    return bin(n).replace("0b", "")


def get_input_iv():
    while True:
        input_iv = input("Enter Initial Value (IV) for encryption in decimal (0-255): ")
        if not check_is_digit(input_iv):
            print("Error you must enter integer")
            continue
        if not check_initial_value(input_iv):
            print("Enter a number between 0-255")
            continue
        else:
            print("Success!!", input_iv, "is your IV")
            break
    return input_iv


def get_input_bob_private_key():
    while True:
        input_pr_b = input("Enter a private key (b) for Bob in decimal: ")
        if not check_is_digit(input_pr_b):
            continue
        else:
            print("Success!!", input_pr_b, "is Bob's private key (b)")
            break
    return input_pr_b


def get_input_alice_private_key():
    while True:
        input_pr_a = input("Enter a private key (a) for Alice in decimal: ")
        if not check_is_digit(input_pr_a):
            continue
        else:
            print("Success!!", input_pr_a, "is Alice's private key (a)")
            break
    return input_pr_a


def get_input_generator(input_prime):
    while True:
        input_generator = input("Enter a generator: ")
        if not check_is_digit(input_generator):
            continue
        if not is_generator(int(input_generator), int(input_prime)):
            print(input_generator, "can not be selected as generator")
            continue
        else:
            print("Success!!", input_generator, "is your generator")
            break
    return input_generator


def get_input_prime():
    while True:
        input_prime = input("Enter a prime number in decimal: ")
        if not check_is_digit(input_prime):
            continue
        if not is_prime(int(input_prime)):
            print(input_prime, "is not prime!!")
            continue
        else:
            print("Success!!", input_prime, "is your prime number")
            break
    return input_prime


def check_is_digit(input_str):
    if input_str.strip().isdigit():
        return True
    else:
        print("Please enter a integer")
        return False


def check_initial_value(input_iv):
    input_iv = int(input_iv)
    return 0 <= input_iv <= 255  # it must 8 bit long to show the results in string to the user


def get_input_msg():
    msg = input("Enter a message to send to Bob:")
    return msg


def main():
    input_prime = get_input_prime()
    input_generator = get_input_generator(input_prime)
    input_pr_a = get_input_alice_private_key()
    input_pr_b = get_input_bob_private_key()
    input_iv = get_input_iv()

    msg = get_input_msg()
    key = generate_key(int(input_generator), int(input_pr_a), int(input_pr_b), int(input_prime))
    print("Your key is generated.")
    print("The common key is: ", key, "in decimal")
    print("------------------------")
    print("Encryption operations starting!!!")
    print("Message in binary: ", str_to_binary(msg))
    enc_msg = encryption(int(input_iv), msg, key)
    enc_msg_str = get_enc_dec_message_in_str(enc_msg)
    print(msg, " is encrypted as -----> ", enc_msg_str)
    print("------------------------")
    print("Message is sent to Bob")
    print("------------------------")
    print("Decryption operations starting!!!")
    dec_msg = decryption(int(input_iv), enc_msg_str, key)
    dec_msg_str = get_enc_dec_message_in_str(dec_msg)
    print("Binary version of the original message: ", str_to_binary(msg).replace(" ", ""))
    print(enc_msg_str, " is decrypted as -----> ", dec_msg_str)
    print("----THE END----")


if __name__ == '__main__':
    main()
