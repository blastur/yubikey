yubikey
=======

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

If you are looking for a complete PHP Yubikey authenticator server, go here:
https://www.yubico.com/develop/open-source-software/validation-server/

If you are looking for a PHP class to authenticate against the official Yubico
servers via its web API, go here:
http://www.yubico.com/develop/open-source-software/web-api-clients/

If you want to build a custom authenticator solution based on YubiKey 
technology, this class may be useful for you.

Usage example
-------------

See example.php for a very basic YubiKey authenticator.

