import com.genesys.datadownload.DecryptUtil;
import com.genesys.datadownload.KeyFileUtil;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.junit.Test;

import javax.mail.MessagingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

public class DecryptingSamples {
  private static final Path PRIVATE_KEY_FILE = Paths.get("sample_files", "private.key");
  private static final Path ENCRYPTED_SMIME_FILE = Paths.get("sample_files", "encrypted.smime");
  private static final Path DECRYPTED_FILE = Paths.get("sample_files", "decrypted.zip");
  private static final Path CERTIFICATE_FILE = Paths.get("sample_files", "cert.pem");

  /** The PureEngage Data Download Service will provide SMIME files with a single recipient. That means that
   * it can be decrypted with just the private key of that recipient. */
  @Test
  public void decrypt_SMIME_with_single_recipient() throws IOException, CMSException, MessagingException {
    AsymmetricKeyParameter privateKey = KeyFileUtil.readPrivateKeyBc(Files.newBufferedReader(PRIVATE_KEY_FILE));
    InputStream decryptedStream = DecryptUtil.decrypt(ENCRYPTED_SMIME_FILE.toFile(), privateKey);
    Files.copy(decryptedStream, DECRYPTED_FILE, REPLACE_EXISTING);
  }

  /** ...alternatively, we can actually make sure that we are the recipient, by comparing with our public certificate. */
  @Test
  public void decrypt_SMIME_looking_up_recipient() throws IOException, CertificateException, CMSException, MessagingException {
    AsymmetricKeyParameter privateKey = KeyFileUtil.readPrivateKeyBc(Files.newBufferedReader(PRIVATE_KEY_FILE));
    X509Certificate certificate = KeyFileUtil.readX509Certificate(Files.newInputStream(CERTIFICATE_FILE));
    InputStream decryptedStream = DecryptUtil.decrypt(ENCRYPTED_SMIME_FILE.toFile(), privateKey, certificate);
    Files.copy(decryptedStream, DECRYPTED_FILE, REPLACE_EXISTING);
  }
}
