package org.matthenry87.nativekeystoretesting;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class NativeKeystoreTestingApplication {

    public static void main(String[] args) throws KeyStoreException {

        var keyService = new KeyService("JCEKS");

        keyService.accessKeyStore();
    }

}

class KeyService {

    private final String keyStoreType;

    public KeyService(String keyStoreType) {

        this.keyStoreType = keyStoreType;
    }

    public void accessKeyStore() throws KeyStoreException {

        Arrays.stream(Security.getProviders())
                .map(Provider::getClass)
                .map(Class::getName)
                .toList()
                .forEach(System.out::println);

        try {

            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, null);

            KeyGenerator keygen = KeyGenerator.getInstance("HmacSHA256");
            SecretKey key = keygen.generateKey();

            keyStore.setKeyEntry("HS256", key, null, null);

        } catch (IOException | KeyStoreException | NoSuchAlgorithmException |
                 CertificateException e) {

            throw new KeyServiceException("Error retrieving key from keystore", e);
        }
    }

    private static class KeyServiceException extends RuntimeException {

        private KeyServiceException(String message, Exception e) {

            super(message, e);
        }

    }

}
