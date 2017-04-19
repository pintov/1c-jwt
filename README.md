1C JWT
=====

This is a pure 1C implementation of `RFC 7519 <https://tools.ietf.org/html/rfc7519>`.

Limitations
-----------

This implementation works only on 1C:Enterprise platform version 8.3.10.2168 or above.
The platform you may download here: <https://1c-dn.com/user/updates/1c_enterprise_platform_training_version/>
Supported algorithm HS256 only.

Installing
----------

Download modules Cryptography.bsl and JWT.bsl.
Put modules into the 1C application.


Usage
-----

```bsl
	SecretKey = "secret";
	Payload = New Structure;
	Payload.Insert("sub", "1234567890");
	Payload.Insert("name", "John Doe");
	Payload.Insert("admin", True);
	
	Token = JWT.Encode(SecretKey, Payload);
	
	DecodedPayload = JWT.Decode(Token, SecretKey);
	
```

Credits and License
-------------------

Author: Vasily Pintov <vasily@pintov.ru>

License: MIT