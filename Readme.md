### JSON Web Key (JWK) tool
--- 
This simple library provides tools for work with private and public keys using RSA 
as [JWK](https://datatracker.ietf.org/doc/html/rfc7517).
The Library allows generating, save and load crypto keys pair based on RSA algorithm. 
JWKS usually use asymmetric encryption keys pair where public key (using in JWKS) for validate the 
[JWT](https://jwt.io/introduction) tokens which signed with private part of keys.
A public key can be placed at different service or server for validate JWT signature.

The Library write in Go and you can either embed to golang projects or use as a standalone application.

##### HOW TO USE
Main items of this library is crypto keys pair. You can generate they or load from some storage. Library supports both of this way (in currently support only RSA keys).
1. Init keys pair with `NewKeys`for create `Key` instance.

Constructor can accept two options:
- Storage - this is interface which has `Load` and `Save` method. They define where keys will be stored and load from. 
User can use pre-defined storage `File` provider in `storage` package. By default, this option is undefined and new generated keys will store in memory only.
Storage `File` provider required path to private and public keys. 
*NOTICE:* Where provider defined, but keys not exist `NewKeys` return error because `Load` can't load keys data.
  
- BitSize - defined size for crypto key which will be generated. Option accept `int` value  By default - 2048.

After `Keys` inited user should check for key exist especially if keys storage provider defined. When keys exist or
generated successfuly you can create JWK key for use it in you services. 
  
```go
keys,err:=NewKeys()
 
if err!=nil {
        // handle error 
}

// Generate new keys pair if need
if err=keys.Generate();err!=nil {
    // handle error
}

err,jwk:=keys.JWK()
if err=keys.Generate();err!=nil {
    // handle error
}

fmt.Println(jwk.ToString())
```
A after execute code above you get result like this:
```javascript
{
          "kty": "RSA",
          "kid": "oI4f",
          "use": "sig",
          "alg": "RS256",
          "n": "n5Y24DhSDIKIN6tJbrOMxfZpoedvAIAA5vKv...",
          "e": "AQAB"
        }
```




 