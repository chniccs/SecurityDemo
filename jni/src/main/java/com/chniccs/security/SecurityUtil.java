package com.chniccs.security;

import android.content.Context;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by ccs on 16/9/9.
 * AES加密工具类
 */
public class SecurityUtil {
    private Cipher cipher = null;
    private final SecretKeySpec key;
    private AlgorithmParameterSpec spec;
    public static String SEED_16_PW;//通过jni取得加密的key
    public static String SEED_16_AES_KEY;//通过jni取得加密的key
    public static SecurityUtil mAESCrypt;

    public static SecurityUtil getInstance() {
        return mAESCrypt;
    }

    public static SecurityUtil init(Context context) {
        if (mAESCrypt == null) {
            mAESCrypt = new SecurityUtil(context);
        }
        return mAESCrypt;
    }


    private SecurityUtil(Context context) {
        SEED_16_AES_KEY = JniUtil.getInstance().getAESkey(context);
        SEED_16_PW = JniUtil.getInstance().getKeyStorePW(context);
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            digest.update(SEED_16_AES_KEY.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        byte[] keyBytes = new byte[32];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        } catch (Exception e) {
            e.printStackTrace();
        }
        key = new SecretKeySpec(keyBytes, "AES");
        spec = getIV();
    }

    public AlgorithmParameterSpec getIV() {
        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,};
        IvParameterSpec ivParameterSpec;
        ivParameterSpec = new IvParameterSpec(iv);
        return ivParameterSpec;
    }

    //根据指定的key来加密
    public String encrypt(String cotent, String aeskey) {
        MessageDigest digest = null;
        byte[] keyBytes = null;
        Cipher cipher = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            digest.update(aeskey.getBytes("UTF-8"));
            keyBytes = new byte[32];
            System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        } catch (Exception e) {
            e.printStackTrace();
        }
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        AlgorithmParameterSpec spec = getIV();
        byte[] encrypted = new byte[0];
        String encryptedText = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            encrypted = cipher.doFinal(cotent.getBytes("UTF-8"));
            encryptedText = new String(Base64.encode(encrypted,
                    Base64.DEFAULT), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return filter(encryptedText);
    }

    //根据指定的key来解密
    public String decrypt(String cryptedText, String aeskey) {
        String decryptedText = null;
        MessageDigest digest = null;
        byte[] keyBytes = null;
        Cipher cipher = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            digest.update(aeskey.getBytes("UTF-8"));
            keyBytes = new byte[32];
            System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            AlgorithmParameterSpec spec = getIV();

            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] bytes = Base64.decode(cryptedText, Base64.DEFAULT);
            byte[] decrypted = cipher.doFinal(bytes);
            decryptedText = new String(decrypted, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedText;
    }


    public String encrypt(String plainText) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        byte[] encrypted = new byte[0];
        try {
            encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        String encryptedText = null;
        try {
            encryptedText = new String(Base64.encode(encrypted,
                    Base64.DEFAULT), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return filter(encryptedText);
    }

    /**
     * 去掉加密字符串换行符
     *
     * @param str
     * @return
     */
    public String filter(String str) {
        String output = "";
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < str.length(); i++) {
            int asc = str.charAt(i);
            if (asc != 10 && asc != 13) {
                sb.append(str.subSequence(i, i + 1));
            }
        }
        output = new String(sb);
        return output;
    }

    public String decrypt(String cryptedText) {
        String decryptedText = null;
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] bytes = Base64.decode(cryptedText, Base64.DEFAULT);
            byte[] decrypted = cipher.doFinal(bytes);
            decryptedText = new String(decrypted, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decryptedText;
    }
}
