package com.genesys.datadownload;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipient;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.bc.BcRSAKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.mail.smime.SMIMEEnvelopedParser;
import org.bouncycastle.mail.smime.util.SharedFileInputStream;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** @noinspection WeakerAccess*/
public class DecryptUtil {

  public static InputStream decrypt(File smimeFile, KeyTransRecipient recipient) throws MessagingException, IOException, CMSException {

    // Notes:
    //
    // We are actually receiving a MIME message, but treating it as a MIME body part prevents
    // to have to create a JavaMail Session and load all providers, which we don't need.
    //
    // This code is inspired by SMIMEToolkit.decrypt, which is not usable, because:
    // - It requires a RecipientId, which we don't require here
    // - It assumes that the plain message was a MIME body part (with headers and contents)
    //
    // MimeBodyPart will read the file into a byte array, unless we pass a SharedInputStream instance.

    return new SMIMEEnvelopedParser(new MimeBodyPart(new SharedFileInputStream(smimeFile)))
        .getRecipientInfos().iterator().next()
        .getContentStream(recipient)
        .getContentStream();
  }

  public static InputStream decrypt(File smimeFile, KeyTransRecipient recipient, KeyTransRecipientId recipientId) throws MessagingException, IOException, CMSException {
    return new SMIMEEnvelopedParser(new MimeBodyPart(new SharedFileInputStream(smimeFile)))
        .getRecipientInfos().get(recipientId)
        .getContentStream(recipient)
        .getContentStream();
  }

  public static InputStream decrypt(File smimeFile, PrivateKey privateKey) throws MessagingException, IOException, CMSException {
    return decrypt(smimeFile, toRecipient(privateKey));
  }

  public static InputStream decrypt(File smimeFile, AsymmetricKeyParameter privateKey) throws MessagingException, IOException, CMSException {
    return decrypt(smimeFile, toRecipient(privateKey));
  }

  public static InputStream decrypt(File smimeFile, AsymmetricKeyParameter privateKey, X509Certificate certificate) throws MessagingException, IOException, CMSException {
    return decrypt(smimeFile, toRecipient(privateKey), toRecipientId(certificate));
  }

  private static KeyTransRecipient toRecipient(PrivateKey privateKey) {
    return new JceKeyTransEnvelopedRecipient(privateKey);
  }

  public static KeyTransRecipient toRecipient(AsymmetricKeyParameter key) {
    return new BcRSAKeyTransEnvelopedRecipient(key);
  }

  public static KeyTransRecipientId toRecipientId(X509Certificate certificate) {
    return new JceKeyTransRecipientId(certificate);
  }
}
