## KMS-signed JWT using Python: boilerplate
This boilerplate repo contains code that you may want to use if you need to implement JWT with KMS generated signature.

### Usage
1. Install dependencies:
```bash
pipenv install
```
2. Update `.env` file to connect to a valid KMS key that you have access to.
3. Enter python shell in virtual env
```bash
pipenv run python
```
4. Run the python code
```python
>>> from main import create_jwt, decode_jwt
>>> encoded_jwt = create_jwt({"iss": "test"})
>>> decoded_jwt = decode_jwt(encoded_jwt)
```
### Reference:
- Though no longer maintained, [jsontokens](https://github.com/blockstack-packages/jsontokens-py/blob/master/jsontokens) provided great reference for the work.
- [PyJWT](https://github.com/jpadilla/pyjwt)
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html)