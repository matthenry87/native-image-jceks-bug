package org.matthenry87.nativekeystoretesting;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class NativeKeystoreTestingApplication {

    public static void main(String[] args) {

        var partnerApiKeystorePassword = System.getenv("PARTNER_API_KEYSTORE_PASSWORD");

//		var keyService = new KeyService("C:\\keystore\\partnerAPIKeyStore", partnerApiKeystorePassword, "JCEKS");
        var keyService = new KeyService("/home/u463254/partnerAPIKeyStore", partnerApiKeystorePassword, "JCEKS");

        var key = keyService.retrieveKey("commhub.jwt.key");

        System.out.println("Done: " + key.toString());
    }

}

class KeyService {

    private final String keyStoreLocation;
    private final String keyStorePassword;
    private final String keyStoreType;

    public KeyService(String keyStoreLocation, String keyStorePassword, String keyStoreType) {
        this.keyStoreLocation = keyStoreLocation;
        this.keyStorePassword = keyStorePassword;
        this.keyStoreType = keyStoreType;
    }

    public Key retrieveKey(String keyName) {

        Arrays.stream(Security.getProviders())
                .map(Provider::getClass)
                .map(Class::getName)
                .toList()
                .forEach(System.out::println);

        try {

            File file = new File(keyStoreLocation);

            try (FileInputStream fis = new FileInputStream(file)) {


                KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                keyStore.load(fis, keyStorePassword.toCharArray());

                var key = keyStore.getKey(keyName, keyStorePassword.toCharArray());

                System.out.println(key.getAlgorithm());

                return key;
            }
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException |
                 CertificateException | UnrecoverableKeyException e) {

            throw new KeyServiceException("Error retrieving key from keystore", e);
        }
    }

    private static class KeyServiceException extends RuntimeException {

        private KeyServiceException(String message, Exception e) {

            super(message, e);
        }

    }

}
