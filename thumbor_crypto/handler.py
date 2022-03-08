# Author Ondrej Barta
# ondrej@ondrej.it
# Copyright 2022

import re

from typing import Any

from thumbor.url import Url
from thumbor.handler_lists import HandlerList
from thumbor.handlers.imaging import ImagingHandler
from thumbor.extension.crypto import url_decrypt

url_compile = re.compile(Url.regex())


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
