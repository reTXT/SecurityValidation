from M2Crypto import Rand, RSA, EVP
from collections import namedtuple
from abc import ABCMeta, abstractmethod
from uuid import UUID
from typing import Callable, Union, Tuple, Optional
from pyasn1.type import univ, char
from pyasn1.codec.der import encoder


class MessageCipher(object):
    __metaclass__ = ABCMeta

    @staticmethod
    def cipher_for_version(version):
        # type: (int) -> MessageCipher
        cipher = {
            1: lambda: V1MessageCipher()
        }.get(version)
        return cipher() if cipher is not None else None

    @staticmethod
    def cipher_for_key(key):
        # type: (bytes) -> MessageCipher
        if len(key) == 48:
            return V1MessageCipher()
        return None

    @abstractmethod
    def generate_key(self):
        # type: () -> bytes
        pass

    @abstractmethod
    def encrypt_key(self, key, public_key):
        # type: (bytes, Union[RSA.RSA,RSA.RSA_pub]) -> bytes
        pass

    @abstractmethod
    def decrypt_key(self, key, private_key):
        # type: (bytes, RSA.RSA) -> bytes
        pass

    @abstractmethod
    def encrypt(self, key, data):
        # type: (bytes, bytes) -> bytes
        pass

    @abstractmethod
    def decrypt(self, key, data):
        # type: (bytes, bytes) -> bytes
        pass


class MessageSigner(object):
    __metaclass__ = ABCMeta

    @staticmethod
    def signer_for_version(version):
        # type: (int, RSA.RSA, RSA.RSA_pub) -> MessageSigner
        signer = {
            1: lambda: V1MessageSigner()
        }.get(version)
        return signer() if signer is not None else None

    @staticmethod
    def signer_for_signature(signature):
        # type: (bytes) -> MessageSigner
        if signature is not None:
            return V1MessageSigner()
        return None

    @abstractmethod
    def sign_msg(self, mid, mtype, sender, recipient, chat_id, meta_data, msg_key, private_key):
        # type: (UUID, int, str, str, Optional[UUID], dict, Optional[bytes], RSA.RSA) -> bytes
        pass

    @abstractmethod
    def verify_msg(self, signature, mid, mtype, sender, recipient, chat_id, meta_data, msg_key, public_key):
        # type: (bytes, UUID, int, str, str, Optional[UUID], dict, Optional[bytes], Union[RSA.RSA,RSA.RSA_pub]) -> bool
        pass

    @abstractmethod
    def sign_direct_msg(self, mid, mtype, sender, recipient_device, meta_data, msg_key, private_key):
        # type: (UUID, str, str, UUID, dict, Optional[bytes], RSA.RSA) -> bytes
        pass

    @abstractmethod
    def verify_direct_msg(self, signature, mid, mtype, sender, recipient_device, meta_data, msg_key, public_key):
        # type: (bytes, UUID, str, str, UUID, dict, Optional[bytes], Union[RSA.RSA,RSA.RSA_pub]) -> bool
        pass


class V1MessageCipher(MessageCipher):
    """
    Message Encryption/Decryption
    Version 1
    ----
    Key Format:
        [16 byte iv][32 byte secret]
        iv:         AES initialization vector
        secret:     AES Key
    ----
    Key Encryption:
        Algorithm:  RSA
        Padding:    PKCS1-OAEP
    ----
    Data Encryption:
        Algorithm:  AES-256
        Padding:    PKCS#7
    ----
    Details:
        When encrypting a key the initialization vector is passed through
        unchanged. While the "secret" is encrypted using the given RSA key.
    """

    ivLength = 16       # AES 256 block length
    secretLength = 32   # AES 256 key length

    def __init__(self):
        super(V1MessageCipher, self).__init__()

    def parse_key(self, key):
        # type: (bytes) -> Tuple[bytes, bytes]
        """
        Parses the key into an initialization vector (iv) and secret (key)/
        :param key: Key in (iv, secret) format
        :return: (iv, secret)
        """
        return namedtuple("Key", ("iv", "secret"))._make((key[0:self.ivLength],
                                                          key[self.ivLength:]))

    def generate_key(self):
        # type: () -> bytes
        """
        Generates a random key in [iv][secret] format.
        :return: Random key as [iv][secret]
        """
        rand = Rand.rand_bytes  # type: Callable[[], bytes]
        iv = rand(self.ivLength)
        secret = rand(self.secretLength)
        return iv + secret

    def encrypt_key(self, key, public_key):
        # type: (bytes, Union[RSA.RSA,RSA.RSA_pub]) -> bytes
        """
        Encrypts the given key.

        Key is in the [iv][secret] format. When encrypting the key, only the secret portion is encrypted. The
        initialization vector (iv) is passed through without alteration.

            [-- IV --][----- SECRET -----]
                |             |
                |             v
                |         RSA-Encrypt
                |             |
                v             v
            [-- IV --][----- SECRET -----]

        :param key: Key in [iv][secret] format
        :param public_key: Public key to encrypt with
        :return: Key with unaltered iv and encrypted secret
        """
        iv, secret = self.parse_key(key)
        return iv + public_key.public_encrypt(secret, RSA.pkcs1_oaep_padding)

    def decrypt_key(self, key, private_key):
        # type: (bytes, RSA.RSA) -> bytes
        """
        Decrypts the given key.

        Key is in the [iv][secret] format. When decrypting the key, only the secret portion is decrypted. The
        initialization vector (iv) is passed through without alteration.

            [-- IV --][----- SECRET -----]
                |             |
                |             v
                |         RSA-Decrypt
                |             |
                v             v
            [-- IV --][----- SECRET -----]

        :param key: Key in [iv][secret] format
        :param private_key: Private key to decrypt with
        :return: Key with unaltered iv and decrypted secret
        """
        iv = key[0:self.ivLength]
        secret = key[self.ivLength:]
        return iv + private_key.private_decrypt(secret, RSA.pkcs1_oaep_padding)

    def encrypt(self, key, data):
        # type: (bytes, bytes) -> bytes
        """
        Encrypts the given data block with the provided key.

        :param key: Key in [iv][secret] format
        :param data: Data to be encrypted
        :return: Encrypted version of data
        """
        iv, secret = self.parse_key(key)
        cipher = EVP.Cipher('aes_256_cbc', secret, iv, op=1)
        return cipher.update(data) + cipher.final()

    def decrypt(self, key, data):
        # type: (bytes, bytes) -> bytes
        """
        Decrypts the given data block with the provided key.

        :param key: Key in [iv][secret] format
        :param data: Data to be decrypted
        :return: Decrypted version of data
        """
        iv, secret = self.parse_key(key)
        cipher = EVP.Cipher('aes_256_cbc', secret, iv, op=0)
        return cipher.update(data) + cipher.final()


class V1MessageSigner(MessageSigner):
    """
    Message Signing
    Version 1
    ----
    Serialization:          ASN.1-DER
    Digest Algorithm:       SHA256
    Encryption Algorithm:   RSA
    ----
    Description:
        Serialization:
            The signing algorithm serializes the arguments by formatting them into ASN.1 sequences and then DER
            encoding the sequences to produces data bytes; ASN.1/DER is a tested method for producing secure & stable
            signatures.
        Digest:
            A message digest is created from the data bytes using the Secure Hashing Algorithm (SHA-256).
        Cryptography:
            The signature is created using RSA signing algorithm.
    """

    digestAlgo = 'sha256'

    def __init__(self):
        super(V1MessageSigner, self).__init__()

    @staticmethod
    def encode(*args):
        # type: (*Union[int, str, UUID, dict, None]) -> bytes
        """
        DER encodes the arguments into an ASN1 structure for signing.
        :param args: Arguments to encode
        :return: DER encoded ASN1 structure
        """
        items = univ.Sequence()
        for idx in range(0, len(args)):
            arg = args[idx]
            if isinstance(arg, int):
                item = univ.Integer(arg)
            elif isinstance(arg, UUID):
                item = univ.OctetString(arg.bytes)
            elif isinstance(arg, str):
                item = univ.OctetString(arg)
            elif isinstance(arg, unicode):
                item = char.UTF8String(arg)
            elif isinstance(arg, dict):
                # Dictionaries are formatted into a sequence of sequences, each
                # sub-sequence containing a key & value of the dictionary
                item = univ.Sequence()
                entry_idx = 0
                for key in sorted(arg.keys()):
                    value = arg[key]
                    entry = univ.Sequence()
                    entry[0] = char.UTF8String(key)
                    entry[1] = char.UTF8String(value)
                    item[entry_idx] = entry
                    entry_idx += 1
            elif arg is None:
                item = univ.Null()
            else:
                raise RuntimeError

            items.setComponentByPosition(idx, item)

        return encoder.encode(items)

    def digest(self, *args):
        # type: (*Union[int, str, UUID, dict, None]) -> bytes
        """
        Encodes the arguments (using DER encoded ASN1) and hashes
        it using the selected digest algorithm.
        :param args: Arguments to encode and digest
        :return: Digest of encoded arguments
        """
        data = self.encode(*args)

        digester = EVP.MessageDigest(self.digestAlgo)
        digester.update(data)
        return digester.final()

    def digest_msg(self, mid, mtype, sender, recipient, chat_id, meta_data, msg_key):
        # type: (UUID, int, str, str, Optional[UUID], dict, Optional[bytes]) -> bytes
        """
        Generates a digest for the Message arguments
        :param mid: Message ID
        :param mtype: Message Type
        :param sender: Sender of the Message
        :param recipient: Recipient of the Message
        :param chat_id: ID of the Group thread (Optional)
        :param meta_data: [String -> String] dictionary
        :param msg_key: Enciphered key for Message data (Optional)
        :return: Digest of encoded Message arguments
        """
        return self.digest(
            mid,
            mtype,
            sender,
            recipient,
            chat_id,
            meta_data,
            msg_key
        )

    def digest_direct_msg(self, mid, mtype, sender, recipient_device, meta_data, msg_key):
        # type: (UUID, str, str, UUID, dict, Optional[bytes]) -> bytes
        """
        Generates a digest for the Message arguments
        :param mid: Message ID
        :param mtype: Message Type
        :param sender: Sender of the Message
        :param recipient_device: ID of the recipient's device
        :param meta_data: [String -> String] dictionary
        :param msg_key: Enciphered key for Message data (Optional)
        :return: Digest of encoded Message arguments
        """
        return self.digest(
            mid,
            mtype,
            sender,
            recipient_device,
            meta_data,
            msg_key
        )

    def sign_msg(self, mid, mtype, sender, recipient, chat_id, meta_data, msg_key, private_key):
        # type: (UUID, int, str, str, Optional[UUID], dict, Optional[bytes], RSA.RSA) -> bytes
        """
        Generates a cryptographic signature for the Message arguments. The arguments
        are ASN1 formatted and DER encoded, digested and a signature is generated.
        :param mid: Message ID
        :param mtype: Message Type
        :param sender: Sender of the Message
        :param recipient: Recipient of the Message
        :param chat_id: ID of the Group thread (Optional)
        :param meta_data: [String -> String] dictionary
        :param msg_key: Enciphered key for Message data (Optional)
        :param private_key: Private key to generate signature
        :return: Cryptographic signature of Message arguments
        """
        digest = self.digest_msg(mid, mtype, sender,  recipient, chat_id, meta_data, msg_key)
        return private_key.sign(digest, self.digestAlgo)

    def verify_msg(self, signature, mid, mtype, sender, recipient, chat_id, meta_data, msg_key, public_key):
        # type: (bytes, UUID, int, str, str, Optional[UUID], dict, Optional[bytes], Union[RSA.RSA,RSA.RSA_pub]) -> bool
        """
        Verifies a cryptographic signature for the Message arguments. The arguments
        are ASN1 formatted and DER encoded, digested and a signature is generated, then
        verified.
        :param signature: Signature to verify
        :param mid: Message ID
        :param mtype: Message Type
        :param sender: Sender of the Message
        :param recipient: Recipient of the Message
        :param chat_id: ID of the Group thread (Optional)
        :param meta_data: [String -> String] dictionary
        :param msg_key: Enciphered key for Message data (Optional)
        :param public_key: Public key to verify signature
        :return: Result of signature verification
        """
        digest = self.digest_msg(mid, mtype, sender,  recipient, chat_id, meta_data, msg_key)
        return bool(public_key.verify(digest, signature, self.digestAlgo))

    def sign_direct_msg(self, mid, mtype, sender, recipient_device, meta_data, msg_key, private_key):
        # type: (UUID, str, str, UUID, dict, Optional[bytes], RSA.RSA) -> bytes
        """
        Generates a cryptographic signature for the Message arguments. The arguments
        are ASN1 formatted and DER encoded, digested and a signature is generated.
        :param mid: Message ID
        :param mtype: Message Type
        :param sender: Sender of the Message
        :param recipient_device: ID of the recipient's device
        :param meta_data: [String -> String] dictionary
        :param msg_key: Enciphered key for Message data (Optional)
        :param private_key: Private key to generate signature
        :return: Cryptographic signature of Message arguments
        """
        digest = self.digest_direct_msg(mid, mtype, sender, recipient_device, meta_data, msg_key)
        return private_key.sign(digest, self.digestAlgo)

    def verify_direct_msg(self, signature, mid, mtype, sender, recipient_device, meta_data, msg_key, public_key):
        # type: (bytes, UUID, str, str, UUID, dict, Optional[bytes], Union[RSA.RSA,RSA.RSA_pub]) -> bytes
        """
        Verifies a cryptographic signature for the Message arguments. The arguments
        are ASN1 formatted and DER encoded, digested and a signature is generated, then
        verified.
        :param signature: Signature to verify
        :param mid: Message ID
        :param mtype: Message Type
        :param sender: Sender of the Message
        :param recipient_device: ID of the recipient's device
        :param meta_data: [String -> String] dictionary
        :param msg_key: Enciphered key for Message data (Optional)
        :param public_key: Public key to verify signature
        :return: Result of signature verification
        """
        digest = self.digest_direct_msg(mid, mtype, sender, recipient_device, meta_data, msg_key)
        return bool(public_key.verify(digest, signature, self.digestAlgo))


__all__ = [
    MessageCipher,
    MessageSigner
]
