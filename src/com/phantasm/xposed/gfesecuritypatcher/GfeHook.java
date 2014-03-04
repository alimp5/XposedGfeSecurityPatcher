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
    	
    	final Class<?> classSecurityPolicy = XposedHelpers.findClass("g.aeb", lpparam.classLoader);
    	if (classSecurityPolicy!=null) {
    		XposedBridge.log("class found : g.aeb");
    	} else {
    		XposedBridge.log("class not found : g.aeb");
    	
    	}
    	
    	de.robv.android.xposed.XC_MethodHook.Unhook u = XposedHelpers.findAndHookMethod(classSecurityPolicy, "a", classPolicy, 
    			XC_MethodReplacement.returnConstant(Integer.valueOf("0"))
    			);
    	
    	if (u!=null) {
    		XposedBridge.log("hook1 successfull");
    	} else {
    		XposedBridge.log("hook1 failed");   	
    	}

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
    	}
    }
}