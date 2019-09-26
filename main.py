#!/usr/bin/python3
import argon2
import bcrypt
import hashlib
import random
import scrypt
import string
import timeit


MESSAGE_LIST_SIZE = 100
MESSAGE_SIZE = 32

BCRYPT_WORK_FACTORS_MIN = 11
BCRYPT_WORK_FACTORS_SUG = 14

PBKDF2_ROUNDS_MIN = 100000
PBKDF2_ROUNDS_SUG = 1000000

SALT = "THISISASALT"

SCRYPT_MIN = {"N": 2**15, "R": 8, "P": 2}
SCRYPT_SUG = {"N": 2**18, "R": 8, "P": 2}

ARGON2_MIN = {"M": 2**17, "T": 4, "P": 8}
ARGON2_SUG = {"M": 2**18, "T": 8, "P": 8}


def pbkdf2_hmac_sha256(password, salt=SALT.encode(), iters=1):
    return hashlib.pbkdf2_hmac(hash_name="sha256", password=password, salt=salt, iterations=iters)


def random_message_generator(size=MESSAGE_SIZE, chars=string.printable):
    return "".join(random.choice(chars) for _ in range(size))


def main():
    print("Message Size: {message_size} characters, rounds: {rounds}".format(message_size=MESSAGE_SIZE,
                                                                             rounds=MESSAGE_LIST_SIZE))
    random_message_list = []

    for x in range(MESSAGE_LIST_SIZE):
        random_message_list.append(random_message_generator())

    # md5 hashing
    start_md5 = timeit.default_timer()
    for random_message in random_message_list:
        hashed_message = hashlib.md5(random_message.encode())
    end_md5 = timeit.default_timer()
    time_spent_md5 = end_md5 - start_md5

    print(
        "The average time spent for MD5 to hash {number_of_messages} messages is: {time_spent}".format(
            number_of_messages=MESSAGE_LIST_SIZE,
            time_spent=str(time_spent_md5 / MESSAGE_LIST_SIZE)
        ))

    # sha256 hashing
    start_sha265 = timeit.default_timer()
    for random_message in random_message_list:
        hashed_message = hashlib.sha256(random_message.encode())
    end_sha256 = timeit.default_timer()
    time_spent_sha256 = end_sha256 - start_sha265

    print(
        "The average time spent for SHA-256 to hash {number_of_messages} messages is: {time_spent}".format(
            number_of_messages=MESSAGE_LIST_SIZE,
            time_spent=str(time_spent_sha256 / MESSAGE_LIST_SIZE)
        ))

    # bcrypt hashing
    for work_factor in BCRYPT_WORK_FACTORS_MIN, BCRYPT_WORK_FACTORS_SUG:
        start_bcrypt = timeit.default_timer()
        for random_message in random_message_list:
            hashed_message = bcrypt.hashpw(random_message.encode(), bcrypt.gensalt(work_factor))
        end_bcrypt = timeit.default_timer()
        time_spent_bcrypt = end_bcrypt - start_bcrypt

        print(
            "The average time spent for bcrypt to hash {number_of_messages} messages with work factor {work_factor} is: {time_spent}".format(
                number_of_messages=MESSAGE_LIST_SIZE,
                work_factor=work_factor,
                time_spent=str(time_spent_bcrypt / MESSAGE_LIST_SIZE)
            ))

    # pbkdf2 hashing
    for rounds in PBKDF2_ROUNDS_MIN, PBKDF2_ROUNDS_SUG:
        start_pbkdf2 = timeit.default_timer()
        for random_message in random_message_list:
            hashed_message = pbkdf2_hmac_sha256(random_message.encode(), iters=rounds)
        end_pbkdf2 = timeit.default_timer()
        time_spent_pbkdf2 = end_pbkdf2 - start_pbkdf2
        print(
            "The average time spent for pbkdf2 to hash {number_of_messages} messages with rounds {rounds} is: {time_spent}".format(
                number_of_messages=MESSAGE_LIST_SIZE,
                rounds=rounds,
                time_spent=str(time_spent_pbkdf2 / MESSAGE_LIST_SIZE)
            ))

    # scrypt hashing
    for params in SCRYPT_MIN, SCRYPT_SUG:
        start_scrypt = timeit.default_timer()
        for random_message in random_message_list:
            hashed_message = scrypt.hash(random_message, SALT, params["N"], params["R"], params["P"], 32)
        end_scrypt = timeit.default_timer()
        time_spent_scrypt = end_scrypt - start_scrypt
        print(
            "The average time spent for scrypt to hash {number_of_messages} messages with N: {N}, R: {R}, P: {P} is: {time_spent}".format(
                number_of_messages=MESSAGE_LIST_SIZE,
                N=params["N"],
                R=params["R"],
                P=params["P"],
                time_spent=str(time_spent_scrypt / MESSAGE_LIST_SIZE)
            ))

    # argon2 id hashing
    for params in ARGON2_MIN, ARGON2_SUG:
        ph = argon2.PasswordHasher(time_cost=params["T"], memory_cost=params["M"], parallelism=params["P"], salt_len=16)
        start_argon2_i = timeit.default_timer()
        for random_message in random_message_list:
            hashed_message = ph.hash(random_message)
        end_argon2_i = timeit.default_timer()
        time_spent_argon2_i = end_argon2_i - start_argon2_i
        print(
            "The average time spent for argon2_id to hash {number_of_messages} messages with T: {T}, M: {M}, P: {P} is: {time_spent}".format(
                number_of_messages=MESSAGE_LIST_SIZE,
                T=params["T"],
                M=params["M"],
                P=params["P"],
                time_spent=str(time_spent_argon2_i / MESSAGE_LIST_SIZE)
            ))


if __name__ == "__main__":
    main()

