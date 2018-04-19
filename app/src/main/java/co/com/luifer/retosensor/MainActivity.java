package co.com.luifer.retosensor;

import android.annotation.SuppressLint;
import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private KeyStore keyStore;
    private static final String Key_NAME="Luifer";
    private Cipher cipher;
    private TextView textView;


    @SuppressLint("NewApi")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        KeyguardManager keyguardManager=(KeyguardManager)getSystemService(KEYGUARD_SERVICE);
        FingerprintManager fingerprintManager= null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            fingerprintManager = (FingerprintManager)getSystemService(FINGERPRINT_SERVICE);
        }

        if (!fingerprintManager.isHardwareDetected()){
            Toast.makeText(this, "fingerprint authentication permission not enable", Toast.LENGTH_SHORT).show();

        }else if (!fingerprintManager.hasEnrolledFingerprints()){
            Toast.makeText(this,"Register at least", Toast.LENGTH_SHORT).show();

        }else if (!keyguardManager.isKeyguardSecure()){

            Toast.makeText(this,"look screen security not enabled",Toast.LENGTH_SHORT).show();
        }else{

            genKey();

            if (cipherInit()){
                FingerprintManager.CryptoObject cryptoObject= new FingerprintManager.CryptoObject(cipher);
                FingerprintHandler helper= new FingerprintHandler(this);
                helper.startAuthentication(fingerprintManager,cryptoObject);
            }
        }
        }

    private boolean cipherInit() {

        try {
                cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();

                try {
                    keyStore.load(null);
                    SecretKey key = null;
                    try {
                        key = (SecretKey) keyStore.getKey(Key_NAME, null);
                    } catch (KeyStoreException e1) {
                        e1.printStackTrace();
                        return false;
                    } catch (UnrecoverableKeyException e1) {
                        e1.printStackTrace();
                        return false;
                    }
                } catch (IOException e1) {
                    e1.printStackTrace();
                    return false;
                } catch (NoSuchAlgorithmException e1) {
                    e1.printStackTrace();
                    return false;
                } catch (CertificateException e1) {
                    e1.printStackTrace();
                    return false;
                }

            }

        return true;
    }

    private void genKey() {
        try {
            keyStore=keyStore.getInstance("AndroidKeyStore");

        }catch (KeyStoreException e){
            e.printStackTrace();
        }
        KeyGenerator  keyGenerator;
        try {
            keyGenerator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        try {
            keyStore.load(null);
                keyGenerator.init(new KeyGenParameterSpec.Builder(Key_NAME,KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setUserAuthenticationRequired(true)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7).build());
            keyGenerator.generateKey();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        catch (InvalidAlgorithmParameterException e){
            e.printStackTrace();
        }

    }

}

