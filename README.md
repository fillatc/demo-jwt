# demo-jwt

A poc to implement JSON Web Tokens with Spring security.
The Open Source Foundation for Application Security (OWASP) provide an excellent cheat sheet on JWT 
with the best practices.


## PROS

+ No need of session storage in backend.
+ Make horizontal scaling easier.

## CONS

+ No session revocation mechanism.
+ Can be more complex to make it secure.


I use thymeleaf for the front part.
The JWT is store in a session cookie and transmitted to the backend.
This JWT can be also transmitted in the header (Authorization: Bearer YOUR_TOKEN) to be able to do 
server to server communication.

What is important is the store properly the JWT to avoid XSS attacks. So no token store in the local 
storage.


### Run with Gitpod

To open a preview in your browser:
```shell
gp preview $(gp url 8080)
```

# Useful links:

https://jwt.io/

https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

https://auth0.com/fr

https://gitpod.io
