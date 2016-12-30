package com.chniccs.security;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;

/**
 *
 *  获得本地化存储的信息的工具类
 */
public class PreferenceUtils {
	
	private static final String SP_NAME="config";
	
	private static SharedPreferences mSp;
	
	public static SharedPreferences getSp(Context context){
		
		if(mSp==null){
			mSp=context.getSharedPreferences(SP_NAME, Context.MODE_PRIVATE);
		}
		return mSp;

	}
	
	public static boolean getBoolean(Context context, String key){
		
		 return getBoolean(context,key,true);
	}
	public static boolean getBoolean(Context context, String key, boolean defValue){
		
		getSp(context);
		
		return mSp.getBoolean(key, defValue);
	}
	
	public static void setBoolean(Context context, String key, boolean value){

		getSp(context);
		
		Editor edit = mSp.edit();
		
		edit.putBoolean(key, value);
		
//		edit.commit();
		edit.apply();
		
	}
	public static String getString(Context context, String key){
		
		return getString(context,key,null);
	}
	public static String getString(Context context, String key, String defValue){
		
		getSp(context);
		
		return mSp.getString(key, defValue);
	}
	
	public static boolean setString(Context context, String key, String value){
		
		getSp(context);
		
		Editor edit = mSp.edit();
		
		edit.putString(key, value);
		
		boolean commit = edit.commit();
		
		return commit;
		
	}
	public static int getInt(Context context, String key){
		
		return getInt(context,key,-1);
	}
	public static int getInt(Context context, String key, int defValue){
		
		getSp(context);
		
		return mSp.getInt(key, defValue);
	}
	
	public static void setInt(Context context, String key, int value){
		
		getSp(context);
		
		Editor edit = mSp.edit();
		
		edit.putInt(key, value);
		
//		edit.commit();
		edit.apply();
		
	}
	
}
