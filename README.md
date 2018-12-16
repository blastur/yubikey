# yubikey

Yubikey is a piece of hardware from Yubico which generates One-Time-Passwords
(OTPs) and transfers them to your computer by emulating a keyboard.

The OTPs look something like this:

	thgegbdkbjgvlecttgrcjltlvebjubdnlurfhvnrubui

The string is an encrypted buffer which has been encoded with modhex (a Yubico-
invented version of base64 encoding).

This PHP class deals with decoding of the modhex, decryption of the data
(provided the 128-bit AES key) and unpacking of the data into more easily
accessible fields.

The class only extracts the information contained in the OTP, it does not carry
out any authentication. It is up to the application to do whatever it wants
with the data.

If you are looking for a complete Yubikey authenticator server, go here:
https://developers.yubico.com/yubikey-val/

If you are looking for a PHP class to authenticate against the official Yubico
servers via its web API, go here:
https://github.com/Yubico/php-yubico

If you want to build a custom authenticator solution based on YubiKey
technology, this class may be useful for you.

## Examples

See examples/ for a very basic YubiKey authenticator.

## Testrun

If you want to testrun this class without installing a full-blown LAMP
installation, the following sequence with Docker can be used:

	$ git clone https://github.com/blastur/yubikey.git
	$ cd yubikey
	$ docker run -it --rm -v "$PWD":/usr/src/yubikey -w /usr/src/yubikey/examples php:7.3-cli bash
	root@378352d1bb27:/usr/src/yubikey/examples# php authenticator.php
	thgegbdkbjgv: authenticated successfully! usage=6 session=0
	thgegbdkbjgv: used/spent token (session)

The docker container will be removed as soon as the shell is exited.