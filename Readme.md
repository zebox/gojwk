### JSON Web Key (JWK) tool
--- 
This simple library provides tools for work with private and public keys using RSA as [JWK](https://datatracker.ietf.org/doc/html/rfc7517).
The Library allows generating, save and load crypto keys pair based on RSA algorithm. 
JWKS usually use asymmetric encryption keys pair where public key (using in JWKS) for validate the [JWT](https://jwt.io/introduction) tokens which signed with private part of keys.
A public key may be placed at different service or server for validate JWT signature.

The Library write in Go and you can either embed to golang projects or use as a standalone application.

##### HOW TO USE
Main items of this library is crypto keys pair. You can generating they or load from some storage. Library support both of this way  (in currently support only RSA keys).



 