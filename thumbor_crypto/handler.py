# Author Ondrej Barta
# ondrej@ondrej.it
# Copyright 2022

import re
import zlib
import base64
import struct
import hashlib
from urllib.parse import unquote
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from typing import Any

from thumbor.url import Url
from thumbor.utils import logger

from thumbor.handler_lists import HandlerList
from thumbor.handlers.imaging import ImagingHandler

url_compile = re.compile(Url.regex())


def url_decrypt(uri, key, block_size=16):
    """
    Vygenerujeme inicializacni vektor z url + hesla prohnano md5
    IV neni random aby fungovala kes prohlizece...
    """
    try:
        url, query = uri.split("?")
    except ValueError:
        logger.error("[Decrypt error] Unauthorized url.")
        return None

    # FB query string url...
    query = unquote(query)

    hash_me = url + key
    iv = hashlib.md5(hash_me.encode())
    # Dorovname base 64 o =
    padding = lambda s: s + "=" * (-len(s) % 4)

    try:
        decoded = base64.b64decode(padding(query))
        crypto_object = AES.new(key=key.encode(), mode=AES.MODE_CBC, IV=iv.digest())
        decrypted = crypto_object.decrypt(decoded[:-4]).rstrip(b"\0")
        try:
            decrypted = unpad(decrypted, block_size=block_size, style="pkcs7")
        except:
            pass

        checksum = zlib.crc32(decrypted) & 0xffffffff
        pack = struct.pack("=L", checksum)
        if decoded[-4:] != pack:
            logger.error("[Decrypt error] Checksum mismatch.")

        return decrypted.decode()
    except:
        logger.error("[Decrypt error] Unauthorized url.")

        return None


class CryptoImagingHandler(ImagingHandler):
    def prepare(self, *args, **kwargs):
        key = self.context.config.CRYPTO_KEY
        decrypted = url_decrypt(self.request.uri, key)
        if decrypted:
            unsafe = "/unsafe/" + decrypted.strip("/")
            result = re.match(url_compile, unsafe)
        else:
            result = None

        if result:
            self.path_kwargs = result.groupdict()
        else:
            self.path_kwargs = {"image": ""}

        super(ImagingHandler, self).prepare(*args, **kwargs)


def get_handlers(context: Any) -> HandlerList:
    return [(r'[a-zA-Z0-9/\.,=_\-]+', CryptoImagingHandler, {"context": context})]
