package com.chniccs.security;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.util.Enumeration;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    public static final String TAG = "TEST";
    public static final String DES = "DES";
    public static final String AES_TOKEN = "aes_token";
    public String token = "fdsfs324nvds";
    private String alias = "chniccs";
    private KeyStore mKeyStore = null;
    char[] chars ;


    /**
     * 流程说明：
     * 通过jni保存存储密码password
     * 通过jni保存加解密secretKey的密钥 password_secretKey
     * 通过KeyGenerator产生一个随机DES加密的64密钥 secretKey
     * （jni中通过签名检验来验证使用者的合法性）
     * <p>
     * ---加密secretKey
     * secretKey 在通过密钥password_secretKey经过AES加密后通过Keystore并经密码password存储在本地沙盒中，称为AESsecretKey
     * ---加密token
     * 在获得token后，通过secretKey对其进行aes加密 得到aes_token
     * ---解密token
     * 在每次要使用token时，先通过keyStore用密码password取得AESsecretKey，通过password_secretKey对AESsecretKey解密得到secretKey,然后对保存的aes_token进行解密,得到token
     * <p>
     * 风险：
     * 手机root后，沙盒中数据会暴露出来，但是经过密码和AES加密后的AESsecretKey并不会有直接的危险性
     * 存储密码password和password_secretKey因为存储在c代码中，并且做了签名检测，如果想破解出来还是比较有难度的。
     */

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        //初始化安全工具类
        SecurityUtil.init(this);
        initView();
        chars = SecurityUtil.SEED_16_PW.toCharArray();

    }

    private void initView() {
        Button sava= (Button) findViewById(R.id.save_secretkey);
        Button encrypt= (Button) findViewById(R.id.encrypt_token);
        Button dcerypt= (Button) findViewById(R.id.decrypt_token);
        sava.setOnClickListener(this);
        encrypt.setOnClickListener(this);
        dcerypt.setOnClickListener(this);
    }

    private void encryptToken() {
        if (mKeyStore == null) {
            try {
                mKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                mKeyStore.load(null,chars);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        try {
            Key key = mKeyStore.getKey(alias, chars);
            String AESsecretKey = new String(key.getEncoded());
            String secretKey = SecurityUtil.getInstance().decrypt(AESsecretKey);
            String encryptToken = SecurityUtil.getInstance().encrypt(token, secretKey);
            Log.d(TAG,"加密后："+ encryptToken);
            PreferenceUtils.setString(this,AES_TOKEN,encryptToken);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private void decryptToken(){
        if (mKeyStore == null) {
            try {
                mKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                mKeyStore.load(null,chars);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        try {
            Key key = mKeyStore.getKey(alias,chars);
            Enumeration<String> aliases = mKeyStore.aliases();
//            while (aliases.hasMoreElements()){
//                Log.d(TAG,aliases.nextElement());
//            }
            String AESsecretKey = new String(key.getEncoded());
            String secretKey = SecurityUtil.getInstance().decrypt(AESsecretKey);
            String decryptToken = SecurityUtil.getInstance().decrypt(PreferenceUtils.getString(this,AES_TOKEN), secretKey);
            Log.d(TAG,"解密后："+ decryptToken);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private void initKeyStore(){
        if (mKeyStore == null) {
            try {
                mKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                File file = new File(this.getFilesDir(), "temp");
                if (!file.exists()) {
                    mKeyStore.load(null, null);
                    file.createNewFile();
                    return;
                }
                FileInputStream in = new FileInputStream(file);
                mKeyStore.load(in, chars);
                in.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }

    private void saveSecretKey() {
        initKeyStore();
//        if (mKeyStore == null) {
//            try {
//                mKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        }

        //对称key即SecretKey创建和导入，假设双方约定使用DES算法来生成对称密钥
        KeyGenerator keyGenerator = null;
        try {
//            File file = new File(this.getFilesDir(), "temp");
//            if (!file.exists()) {
//                mKeyStore.load(null, null);
//                file.createNewFile();
//                return;
//            }
//            FileInputStream in = new FileInputStream(file);
//            mKeyStore.load(in, chars);
//            in.close();
            keyGenerator = KeyGenerator.getInstance("DES");
            keyGenerator.init(64);
            //生成SecretKey对象，即创建一个对称密钥，并获取二进制的书面表达
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] keyData = secretKey.getEncoded();
            Log.d(TAG, new String(keyData));
            //对生成的SecretKey进行aes加密
            String encryptData = SecurityUtil.getInstance().encrypt(new String(keyData));
            mKeyStore.load(null, chars);
            //指定类型为PBE
            PBEKeySpec keySpec = new PBEKeySpec(encryptData.toCharArray());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWITHSHA1ANDDES");
            //通过工厂生成key
            SecretKey key = keyFactory.generateSecret(keySpec);
            KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(key);
            //设置密码保护
           final KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(chars);
            //存储
            mKeyStore.setEntry(alias, entry, passwordProtection);
            KeyStore.LoadStoreParameter loadStoreParameter=new KeyStore.LoadStoreParameter() {
                @Override
                public KeyStore.ProtectionParameter getProtectionParameter() {
                    return passwordProtection;
                }
            };
            mKeyStore.store(loadStoreParameter);
            Key anchu = mKeyStore.getKey(alias, chars);
            Log.d(TAG, new String(anchu.getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    /** */
    /**
     * 把字节数组转换成16进制字符串
     *
     * @param bArray
     * @return
     */
    public static final String bytesToHexString(byte[] bArray) {
        StringBuffer sb = new StringBuffer(bArray.length);
        String sTemp;
        for (int i = 0; i < bArray.length; i++) {
            sTemp = Integer.toHexString(0xFF & bArray[i]);
            if (sTemp.length() < 2)
                sb.append(0);
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()){
            case R.id.save_secretkey:
                saveSecretKey();
                break;
            case R.id.encrypt_token:
                encryptToken();
                break;
            case R.id.decrypt_token:
                decryptToken();
                break;
        }
    }
}
