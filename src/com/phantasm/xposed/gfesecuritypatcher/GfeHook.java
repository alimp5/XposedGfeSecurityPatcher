package com.phantasm.xposed.gfesecuritypatcher;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class GfeHook implements IXposedHookLoadPackage {
	private static final String PACKAGE_EMAIL = "com.good.android.gfe";
	
	@Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
    	if (!lpparam.packageName.equals(PACKAGE_EMAIL))
            return;
    	
    	XposedBridge.log("Loaded app: " + lpparam.packageName);

    	final Class<?> classPolicy = XposedHelpers.findClass("com.good.android.compliance.ComplianceManagerPolicy", lpparam.classLoader);  	   	
    	
    	if (classPolicy!=null) {
    		XposedBridge.log("class found : com.good.android.compliance.ComplianceManagerPolicy");
    	} else {   	
    		XposedBridge.log("class not found : com.good.android.compliance.ComplianceManagerPolicy");
    	}
    	
    	//older version of gfe
    	Class<?> classSecurityPolicy = XposedHelpers.findClass("g.aeb", lpparam.classLoader);
    	if (classSecurityPolicy!=null) {
    		XposedBridge.log("class found : g.aeb");
			de.robv.android.xposed.XC_MethodHook.Unhook u;			
			try
			{
				u = XposedHelpers.findAndHookMethod(classSecurityPolicy, "a", classPolicy, 
						XC_MethodReplacement.returnConstant(Integer.valueOf("0"))
        			);
			}
			catch (java.lang.Throwable e)
			{
				u = null; 
				XposedBridge.log("hook1 g.aeb fail");
			}				
       	
        	if (u!=null) {
        		XposedBridge.log("hook1 successful");
        	} else {
        		XposedBridge.log("hook1 failed");   	
        	}

    	
    	} else {
    		XposedBridge.log("class not found : g.aeb");    	
    	}
    	
    	//gfe version dated 02-Jun-2014
		classSecurityPolicy = XposedHelpers.findClass("g.agc", lpparam.classLoader);
		if (classSecurityPolicy!=null) {
			XposedBridge.log("class found : g.agc");

			de.robv.android.xposed.XC_MethodHook.Unhook u;			
			try
			{
				u = XposedHelpers.findAndHookMethod(classSecurityPolicy, "a", classPolicy, 
						XC_MethodReplacement.returnConstant(Integer.valueOf("0"))
        			);
			}
			catch (java.lang.Throwable e)
			{
				u = null; 
				XposedBridge.log("hook1 g.agc fail");
				
			}				
       	
        	if (u!=null) {
        		XposedBridge.log("hook1 successful");
        	} else {
        		XposedBridge.log("hook1 failed");   	
        	}

		
		} else {
			XposedBridge.log("class not found : g.agc");   	
		}

		//this attempts a more generic hook in case the above stuff fails
    	final Class<?> classPolicy2 = XposedHelpers.findClass("com.good.android.compliance.d", lpparam.classLoader);  	   	

    	if (classPolicy2!=null) {
    		XposedBridge.log("class found : com.good.android.compliance.d");
    	} else {   	
    		XposedBridge.log("class not found : com.good.android.compliance.d");
    	}    	
    	
    	de.robv.android.xposed.XC_MethodHook.Unhook u2;
		
		try
		{	
			u2 = XposedHelpers.findAndHookMethod(classPolicy2, "a", 
    			XC_MethodReplacement.returnConstant(Integer.valueOf("0"))
    			);
		}
		catch (java.lang.Throwable e)
		{
			u2 = null;		
		}
		
    	if (u2!=null) {
    		XposedBridge.log("hook2 successfull");
    	} else {
    		XposedBridge.log("hook2 failed");   	
    	}
    	
    	de.robv.android.xposed.XC_MethodHook.Unhook u3;
    	
    	try
    	{
    		u3 = XposedHelpers.findAndHookMethod(classPolicy2, "a", int.class, XC_MethodReplacement.returnConstant(Boolean.valueOf(false))
    			);
    	}
    	catch (java.lang.Throwable e)
    	{
    		u3 = null;
    	}
    	
    	if (u3!=null) {
    		XposedBridge.log("hook3 successfull");
    	} else {
    		XposedBridge.log("hook3 failed");   	
    	}

    	/* this patch was intended to try and disable the lock password - but it does not work and should not be included	
		
		final Class<?> classSecurityPolicy2 = XposedHelpers.findClass("g.ano", lpparam.classLoader);  	   	
    	
    	if (classSecurityPolicy2!=null) {
    		XposedBridge.log("class found : g.ano");
    	} else {   	
    		XposedBridge.log("class not found : g.ano");
    	}
    	
    	de.robv.android.xposed.XC_MethodHook.Unhook u2 = XposedHelpers.findAndHookMethod(classSecurityPolicy2, "s", XC_MethodReplacement.returnConstant(Boolean.valueOf(false))
    			);
    	
    	if (u2!=null) {
    		XposedBridge.log("hook2 successfull");
    	} else {
    		XposedBridge.log("hook2 failed");   	
    	}*/
    }
}