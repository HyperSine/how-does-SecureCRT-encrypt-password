#!/usr/bin/env python3
import os, struct
from Crypto.Hash import SHA256, SHA512
from Crypto.Cipher import AES, Blowfish
from Crypto.Protocol import KDF

def bcrypt_hash(password: bytes, salt: bytes) -> bytes:
    password = SHA512.new(password).digest()
    salt = SHA512.new(salt).digest()

    digest = KDF._bcrypt_hash(password, 6, salt, b'OxychromaticBlowfishSwatDynamite', False)
    digest = b''.join(digest[i:i + 4][::-1] for i in range(0, len(digest), 4))

    return digest

def bcrypt_pbkdf2(password: bytes, salt: bytes, key_length: int, rounds: int) -> bytes:
    BCRYPT_BLOCKS = 8
    BCRYPT_HASHSIZE = BCRYPT_BLOCKS * 4

    out_len = (key_length + BCRYPT_HASHSIZE - 1) // BCRYPT_HASHSIZE * BCRYPT_HASHSIZE
    out = KDF.PBKDF2(password, salt, out_len, rounds, prf = bcrypt_hash)

    stride_n = (key_length + BCRYPT_HASHSIZE - 1) // BCRYPT_HASHSIZE
    return bytes(out[sum(a * b for a, b in zip(divmod(i, stride_n), (1, BCRYPT_HASHSIZE)))] for i in range(0, key_length))

class SecureCRTCrypto:

    def __init__(self) -> None:
        '''
        Initialize SecureCRTCrypto object.
        '''
        self._iv = b'\x00' * Blowfish.block_size
        self._key1 = b'\x24\xA6\x3D\xDE\x5B\xD3\xB3\x82\x9C\x7E\x06\xF4\x08\x16\xAA\x07'
        self._key2 = b'\x5F\xB0\x45\xA2\x94\x17\xD9\x16\xC6\xC6\xA2\xFF\x06\x41\x82\xB7'

    def encrypt(self, plaintext: str) -> str:
        '''
        Encrypt `plaintext` and return the corresponding ciphertext.

        Args:
            plaintext (str): An ASCII string to encrypt.

        Returns:
            str: The hexlified ciphertext string.
        '''
        plaintext_bytes = plaintext.encode('utf-16-le')
        plaintext_bytes += b'\x00\x00'

        plaintext_bytes_padded = \
            plaintext_bytes + os.urandom(Blowfish.block_size - len(plaintext_bytes) % Blowfish.block_size)

        cipher1 = Blowfish.new(self._key1, Blowfish.MODE_CBC, iv = self._iv)
        cipher2 = Blowfish.new(self._key2, Blowfish.MODE_CBC, iv = self._iv)
        return cipher1.encrypt(os.urandom(4) + cipher2.encrypt(plaintext_bytes_padded) + os.urandom(4)).hex()
    
    def decrypt(self, ciphertext: str) -> str:
        '''
        Decrypt `ciphertext` and return the corresponding plaintext.

        Args:
            ciphertext (str): A hex string to decrypt.

        Returns:
            str: The plaintext string.
        '''
        cipher1 = Blowfish.new(self._key1, Blowfish.MODE_CBC, iv = self._iv)
        cipher2 = Blowfish.new(self._key2, Blowfish.MODE_CBC, iv = self._iv)

        ciphertext_bytes = bytes.fromhex(ciphertext)
        if len(ciphertext_bytes) <= 8:
            raise ValueError('Bad ciphertext: too short!')
        
        plaintext_bytes_padded = cipher2.decrypt(cipher1.decrypt(ciphertext_bytes)[4:-4])

        null_terminator_index = -1
        for i in range(0, len(plaintext_bytes_padded), 2):
            if plaintext_bytes_padded[i] == 0 and plaintext_bytes_padded[i + 1] == 0:
                null_terminator_index = i
                break
        if null_terminator_index < 0:
            raise ValueError('Bad ciphertext: null terminator is not found.')
        else:
            padding_len = len(plaintext_bytes_padded) - (null_terminator_index + 2)
            assert(padding_len >= 0)

            if padding_len != Blowfish.block_size - (null_terminator_index + 2) % Blowfish.block_size:
                raise ValueError('Bad ciphertext: incorrect padding.')

        plaintext_bytes = plaintext_bytes_padded[0:null_terminator_index]

        try:
            return plaintext_bytes.decode('utf-16-le')
        except UnicodeDecodeError:
            raise ValueError('Bad ciphertext: not UTF16-LE encoded.')

class SecureCRTCryptoV2:

    def __init__(self, config_passphrase: str = ''):
        '''
        Initialize SecureCRTCryptoV2 object.

        Args:
            config_passphrase (str): The config passphrase that SecureCRT uses. Leave it empty if config passphrase is not set.
        '''
        self._config_passphrase = config_passphrase.encode('utf-8')

    def encrypt(self, plaintext: str, **kwargs) -> str:
        '''
        Encrypt `plaintext` and return the corresponding ciphertext.

        Args:
            plaintext (str): An ASCII string to encrypt.
            **kwargs: Some keyword arguments.

        Returns:
            str: The hexlified ciphertext string.
        '''
        plaintext_bytes = plaintext.encode('utf-8')
        prefix = kwargs.get('prefix', '03')

        if len(plaintext_bytes) > 0xffffffff:
            raise OverflowError('Bad plaintext: too long!')
        
        if prefix == '02':
            cipher = AES.new(SHA256.new(self._config_passphrase).digest(), AES.MODE_CBC, iv = b'\x00' * AES.block_size)
        elif prefix == '03':
            salt = os.urandom(16)
            kdf_bytes = bcrypt_pbkdf2(self._config_passphrase, salt, 32 + AES.block_size, 16)
            cipher = AES.new(kdf_bytes[:32], mode = AES.MODE_CBC, iv = kdf_bytes[32:])
        else:
            raise NotImplementedError('Unknown prefix: {}'.format(prefix))
        
        # lvc: l -> length, v -> value, c -> checksum
        lvc_bytes = struct.pack('<I', len(plaintext_bytes)) + plaintext_bytes + SHA256.new(plaintext_bytes).digest()
        
        if prefix == '02':
            padding_len = AES.block_size - len(lvc_bytes) % AES.block_size
        elif prefix == '03':
            padding_len = AES.block_size - len(lvc_bytes) % AES.block_size
            if padding_len < AES.block_size // 2:
                padding_len += AES.block_size
        else:
            raise NotImplementedError('Unknown prefix: {}'.format(prefix))
        
        ciphertext_bytes = cipher.encrypt(lvc_bytes + os.urandom(padding_len))
        if prefix == '03':
            ciphertext_bytes = salt + ciphertext_bytes

        return ciphertext_bytes.hex()

    def decrypt(self, ciphertext: str, **kwargs) -> str:
        '''
        Decrypt `ciphertext` and return the corresponding plaintext.

        Args:
            ciphertext (str): A hex string to be decrypt.
            **kwargs: Some keyword arguments.

        Returns:
            str: The plaintext string.
        '''
        ciphertext_bytes = bytes.fromhex(ciphertext)
        prefix = kwargs.get('prefix', '03')
        
        if prefix == '02':
            cipher = AES.new(SHA256.new(self._config_passphrase).digest(), AES.MODE_CBC, iv = b'\x00' * AES.block_size)
        elif prefix == '03':
            if len(ciphertext_bytes) < 16:
                raise ValueError('Bad ciphertext: too short!')
            salt, ciphertext_bytes = ciphertext_bytes[:16], ciphertext_bytes[16:]
            kdf_bytes = bcrypt_pbkdf2(self._config_passphrase, salt, 32 + AES.block_size, 16)
            cipher = AES.new(kdf_bytes[:32], mode = AES.MODE_CBC, iv = kdf_bytes[32:])
        else:
            raise NotImplementedError('Unknown prefix: {}'.format(prefix))

        padded_bytes = cipher.decrypt(ciphertext_bytes)
        
        plaintext_len, = struct.unpack('<I', padded_bytes[0:4])
        if len(padded_bytes) < 4 + plaintext_len:
            raise ValueError('Bad ciphertext: incorrect plaintext length.')

        plaintext_bytes = padded_bytes[4:][:plaintext_len]
        if len(padded_bytes) < 4 + plaintext_len + SHA256.digest_size:
            raise ValueError('Bad ciphertext: missing sha256 checksum.')

        checksum_bytes = padded_bytes[4 + plaintext_len:][:SHA256.digest_size]
        padding_bytes = padded_bytes[4 + plaintext_len + SHA256.digest_size:]

        if prefix == '02':
            expected_padding_len = AES.block_size - (4 + plaintext_len + SHA256.digest_size) % AES.block_size
        elif prefix == '03':
            expected_padding_len = AES.block_size - (4 + plaintext_len + SHA256.digest_size) % AES.block_size
            if expected_padding_len < AES.block_size // 2:
                expected_padding_len += AES.block_size
        else:
            raise NotImplementedError('Unknown prefix: {}'.format(prefix))

        if len(padding_bytes) != expected_padding_len:
            raise ValueError('Bad ciphertext: incorrect padding.')

        if SHA256.new(plaintext_bytes).digest() != checksum_bytes:
            raise ValueError('Bad ciphertext: incorrect sha256 checksum.')

        return plaintext_bytes.decode('utf-8')

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest = 'OPERATION', required = True)

    enc_subparser = subparsers.add_parser('enc', help = 'perform encrypt operation')
    dec_subparser = subparsers.add_parser('dec', help = 'perform decrypt operation')

    enc_subparser.add_argument(
        '-2', '--v2',
        action = 'store_true',
        help = 'encrypt/decrypt with "Password V2" algorithm'
    )
    enc_subparser.add_argument(
        '--prefix',
        action = 'store',
        type = str,
        choices = ['02', '03'],
        default = '03',
        help = 'the prefix of encrypted passwords generated with "Password V2" algorithm'
    )
    enc_subparser.add_argument(
        '-p', '--passphrase',
        action = 'store',
        type = str,
        help = 'the config passphrase that SecureCRT uses'
    )
    enc_subparser.add_argument(
        'PASSWORD',
        type = str,
        help = 'the plain password to encrypt'
    )

    dec_subparser.add_argument(
        '-2', '--v2',
        action = 'store_true',
        help = 'encrypt/decrypt with "Password V2" algorithm'
    )
    dec_subparser.add_argument(
        '--prefix',
        action = 'store',
        type = str,
        choices = ['02', '03'],
        default = '03',
        help = 'the prefix of encrypted passwords generated with "Password V2" algorithm'
    )
    dec_subparser.add_argument(
        '-p', '--passphrase',
        action = 'store',
        type = str,
        help = 'the config passphrase that SecureCRT uses'
    )
    dec_subparser.add_argument(
        'PASSWORD',
        type = str,
        help = 'the encrypted password to reveal'
    )

    args = parser.parse_args()

    if args.OPERATION == 'enc':
        operation = 'encrypt'
    elif args.OPERATION == 'dec':
        operation = 'decrypt'
    else:
        raise NotImplementedError('Unknown operation: {}'.format(args.OPERATION))

    if args.v2:
        cipher = SecureCRTCryptoV2() if args.passphrase is None else SecureCRTCryptoV2(args.passphrase)
        print(getattr(cipher, operation)(args.PASSWORD, prefix = args.prefix))
    else:
        cipher = SecureCRTCrypto()
        print(getattr(cipher, operation)(args.PASSWORD))
