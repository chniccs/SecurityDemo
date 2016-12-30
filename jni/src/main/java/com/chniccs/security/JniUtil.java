package com.chniccs.security;

/**
 * Created by ccs on 16/12/29.
 */

public class JniUtil {
    private static JniUtil mJniUtil;
    static {
        System.loadLibrary("chniccsJni");
    }
    public static JniUtil getInstance(){
        if(mJniUtil==null){
            mJniUtil=new JniUtil();
        }
        return mJniUtil;
    }
    public native String  getKeyStorePW(Object context);
    public native String  getAESkey(Object context);
}
