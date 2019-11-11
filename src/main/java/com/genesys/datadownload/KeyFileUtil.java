package com.genesys.datadownload;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/** Utility methods for reading keys and certificates from files. */
public class KeyFileUtil {

  /**
   * @throws IOException in case of a parsing or decoding error.
   */
  public static PrivateKey readPrivateKeyJca(Reader pemFile) throws IOException {
    PEMKeyPair pemKeyPair = (PEMKeyPair) new PEMParser(pemFile).readObject();
    KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
    return keyPair.getPrivate();
  }

  /**
   * @throws IOException in case of a parsing or decoding error.
   */
  public static AsymmetricKeyParameter readPrivateKeyBc(Reader pemFile) throws IOException {
    PEMKeyPair pemKeyPair = (PEMKeyPair) new PEMParser(pemFile).readObject();
    PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
    return PrivateKeyFactory.createKey(privateKeyInfo);
  }

  public static X509Certificate readX509Certificate(InputStream file) throws CertificateException {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(file);
  }

  public static X509Certificate readX509CertificateBc(InputStream file) throws CertificateException {
    return (X509Certificate)
        new org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory().engineGenerateCertificate(file);
  }

  /** Not sure how this way of reading the certificate would be used. */
  public static X509CertificateHolder readX509CertificateHolder(InputStream file) throws IOException {
    return (X509CertificateHolder) new PEMParser(new InputStreamReader(file)).readObject();
  }

}
