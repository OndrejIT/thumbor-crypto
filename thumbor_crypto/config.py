# Author Ondrej Barta
# git@ondrej.it
# Copyright 2022


from thumbor.config import Config, config


Config.define(
    "CRYPTO_KEY",
    None,
    "Enter the encryption key",
    "Crypto key",
)


def __generate_config():
    config.generate_config()


if __name__ == "__main__":
    __generate_config()
