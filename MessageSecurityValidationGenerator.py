import json
from base64 import b64encode
from MessageSecurity import MessageCipher, MessageSigner
from M2Crypto import RSA, BIO
from uuid import UUID
from collections import namedtuple


MsgInput = namedtuple('MsgInput', ('id', 'type', 'sender', 'recipient', 'chat_id', 'meta_data', 'key', 'data'))
DMsgInput = namedtuple('DMsgInput', ('id', 'type', 'sender', 'recipient_device', 'meta_data', 'key', 'data'))


class Generator(object):
    """
    Generates a data file for validating encryption & signing
    methods against the algorithms used in MessageSecurity.
    """

    keys = RSA.gen_key(2048, 65537)

    def generate(self):
        # type: () -> dict
        data = dict()

        bio = BIO.MemoryBuffer()
        self.keys.save_key_der_bio(bio)
        data['key'] = b64encode(bio.read())

        input_variations = self.generate_test_variations()

        data['tests'] = list()
        for input_variation in input_variations:
            test_data = dict()
            test_data['input'] = input_variation
            test_data['versions'] = dict()
            for version in range(1, 2):
                cipher = MessageCipher.cipher_for_version(version)
                key = None if not input_variation.key else cipher.generate_key()
                enciphered_key = None if not input_variation.key else cipher.encrypt_key(key, self.keys)
                signer = MessageSigner.signer_for_version(version)
                test_data['versions'][version] = {
                    'signature': Generator.sign(signer, input_variation, enciphered_key, self.keys),
                    'decipheredKey': None if key is None else b64encode(key),
                    'encipheredKey': None if enciphered_key is None else b64encode(enciphered_key),
                    'data': None if not input_variation.key else Generator.encrypt(cipher, key, input_variation.data)
                }
            data['tests'].append(test_data)
        return data

    @staticmethod
    def generate_test_variations():
        # type: () -> Sequence[Union[MsgInput, DMsgInput]]
        id1 = UUID('6654FD11-466A-49ED-902B-114C6B61CE5F')
        id2 = UUID('3FA2A78A-4829-4EB3-8928-6F194E5F07BF')
        return (
            MsgInput._make((id1, 1, u'me', u'you', id2, {}, True, 'Hello World!')),
            MsgInput._make((id1, 1, u'me', u'you', id2, {u't': u'html', u'id': u'5'}, True, 'Hello World!')),
            MsgInput._make((id1, 1, u'me', u'you', None, {}, True, 'Hello World!')),
            MsgInput._make((id1, 1, u'me', u'you', id2, {}, False, 'Hello World!')),
            MsgInput._make((id1, 1, u'me', u'you', id2, {u't': u'html', u'id': u'5'}, False, 'Hello World!')),
            MsgInput._make((id1, 1, u'me', u'you', None, {u't': u'html', u'id': u'5'}, False, 'Hello World!')),
            MsgInput._make((id1, 1, u'me', u'you', id2, {}, False, None)),
            MsgInput._make((id1, 1, u'me', u'you', id2, {u'c': u'del', u'id': u'5'}, False, None)),
            MsgInput._make((id1, 1, u'me', u'you', None, {}, False, None)),
            MsgInput._make((id1, 1, u'me', u'you', None, {u'c': u'del', u'id': u'5'}, False, None)),

            DMsgInput._make((id1, u'key', u'me', id2, {}, True, u'Hello World!')),
            DMsgInput._make((id1, u'key', u'me', id2, {u'type': u'text/html'}, True, u'Hello World!')),
            DMsgInput._make((id1, u'key', u'me', id2, {}, False, u'Hello World!')),
            DMsgInput._make((id1, u'key', u'me', id2, {u'type': u'text/html'}, False, u'Hello World!')),
            DMsgInput._make((id1, u'key', u'me', id2, {}, False, None)),
            DMsgInput._make((id1, u'key', u'me', id2, {u'command': u'go'}, False, None)),
        )

    @staticmethod
    def encrypt(cipher, key, data):
        # type: (MessageCipher, bytes, str) -> bytes
        if data is None:
            return None
        return b64encode(cipher.encrypt(key, data.encode('utf-8')))

    @staticmethod
    def sign(signer, iv, key, private_key):
        # type: (MessageSigner, Union[MsgInput, DMsgInput], bytes, RSA.RSA) -> bytes
        if isinstance(iv, MsgInput):
            sig = signer.sign_msg(iv.id, iv.type, iv.sender, iv.recipient, iv.chat_id, iv.meta_data, key, private_key)
        elif isinstance(iv, DMsgInput):
            sig = signer.sign_direct_msg(iv.id, iv.type, iv.sender, iv.recipient_device, iv.meta_data, key, private_key)
        else:
            raise RuntimeError
        return b64encode(sig)


def cast(val):
    if isinstance(val, UUID):
        return str(val)
    raise TypeError


if __name__ == '__main__':
    f = file("message_security_validation.json", "w")
    json.dump(Generator().generate(), f, indent=2, default=cast)
    f.close()
