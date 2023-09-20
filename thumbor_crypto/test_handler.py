# Author Ondrej Barta
# ondrej@ondrej.it
# Copyright 2022-2023

import re
import zlib
import base64
import struct
import hashlib
from urllib.parse import parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from typing import Any

from thumbor.url import Url
from thumbor.utils import logger

from thumbor.handler_lists import HandlerList
from thumbor.handlers.imaging import ImagingHandler

url_compile = re.compile(Url.regex())


def url_decrypt(uri):
    try:
        url, query = uri.split("?")
    except ValueError:
        logger.error("[Decrypt error] Unauthorized url.")
        return None

    try:
        # Remove other query params
        query = parse_qs(query)["th"][0]
    except (KeyError, IndexError):
        pass

    logger.debug("[Url] " + url)
    logger.debug("[Query] " + query)

    return query


class CryptoImagingHandler(ImagingHandler):
    def prepare(self, *args, **kwargs):
        decrypted = url_decrypt(self.request.uri)
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
