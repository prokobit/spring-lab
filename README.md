# spring-lab

```bash
  keytool -genkeypair -alias baeldung -keyalg RSA -keysize 4096 \
    -validity 3650 -dname "CN=localhost" -keypass changeit -keystore keystore.p12 \
    -storeType PKCS12 -storepass changeit
```