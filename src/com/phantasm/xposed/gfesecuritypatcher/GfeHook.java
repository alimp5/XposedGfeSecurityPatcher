package com.phantasm.xposed.gfesecuritypatcher;

import java.lang.reflect.Method;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;
import java.util.ArrayList;

public class GfeHook implements IXposedHookLoadPackage {
	private static Class<?> classPolicy = null;
	private static final String PACKAGE_EMAIL = "com.good.android.gfe";
	
	private boolean processClass(Class<?> a)
	{
		if (a!=null)
    	{
    		XposedBridge.log("class found : "+a.getName());
    		
    		//de.robv.android.xposed.XC_MethodHook.Unhook u;		

    		Method[] methods = a.getDeclaredMethods();
    		String decryptMethodName = "";
    		for (Method method : methods) {
				Class<?>[] methodParams = method.getParameterTypes();
				if ((method.getReturnType().getName().contains("Class")) && (methodParams.length==1) && (methodParams[0].getName().contains("String")))
						{
							decryptMethodName = method.getName();
							XposedBridge.log("probable decryption method found : "+decryptMethodName);
					
						}
    		}
    		
    		if (!decryptMethodName.equals("")) 
    			XposedHelpers.findAndHookMethod(a,decryptMethodName , String.class,
    				new XC_MethodHook() {
					
    			@Override
    			protected void afterHookedMethod(MethodHookParam param) throws Throwable {

   				
    				final String classname = (String) param.args[0];   				
    				final Class<?> a = (Class<?>) param.getResult();	
    				
    				if (classname.equals("g.cs"))
    				{
    		    		XposedBridge.log("method hook - "+classname+" found");

    		    		/*Method[] methods = a.getDeclaredMethods();
    		    		for (Method gcsmethod : methods) {
        		    		XposedBridge.log("g.cs method - "+gcsmethod.getName()+" return type - "+gcsmethod.getReturnType().getName());
    		    			Class<?>[] gcsmethodparamTypes = gcsmethod.getParameterTypes();
        		    		for (Class<?> methodparam : gcsmethodparamTypes) {
    		    				XposedBridge.log("    parameter: "+methodparam.getName());
        		    		}
    		    		}*/
    		    		
    		    		XposedHelpers.findAndHookMethod(a, "i",
    		    				
    		    				new XC_MethodReplacement() {
    						
    		    			@Override
    		    			protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
    		    				XposedBridge.log("method call to g.cs->i intercepted - returning false");
    		    				return false;
    		    			}
    		    		});  		    		

    		    		XposedHelpers.findAndHookMethod(a, "o",  
    		    				
    		    				new XC_MethodReplacement() {
    						
    		    			@Override
    		    			protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
    		    				XposedBridge.log("method call to g.cs->o intercepted - returning empty list");
    		    				return new ArrayList();
    		    			}
    		    		});  		    		

    		    		XposedHelpers.findAndHookMethod(a, "p",
    		    				
    		    				new XC_MethodReplacement() {
    						
    		    			@Override
    		    			protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
    		    				XposedBridge.log("method call to g.cs->p intercepted - returning false");
    		    				return false;
    		    			}
    		    		});  		    		
    					
    		    		XposedHelpers.findAndHookMethod(a, "q",
    		    				
    		    				new XC_MethodReplacement() {
    						
    		    			@Override
    		    			protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
    		    				XposedBridge.log("method call to g.cs->q intercepted - returning false");
    		    				return false;
    		    			}
    		    		});  		    		

    				}
    				
    				if (classname.equals("g.ahp"))
    				{   					

    					//de.robv.android.xposed.XC_MethodHook.Unhook u;		
    		    			    		
    		    		XposedBridge.log("method hook - "+classname+" found");
        				
    		    		Method[] methods = a.getDeclaredMethods();
    		    		
    		    		Method foundMethod = null;
    		    		for (Method method : methods) {

    		    			if (method.getName().equals("a"))
	    					{
	
	    		    			Class<?>[] methodparamTypes = method.getParameterTypes();
	        		    		/*for (Class<?> methodparam : methodparamTypes) {
	    		    				XposedBridge.log("    parameter: "+methodparam.getName());
	        		    		}*/
	        		    		
	        		    		if (methodparamTypes.length==1 && methodparamTypes[0].getName().equals("g.cs")) 
	        		    			{
	        		    				foundMethod = method;
	        		    			}
	    					}

    		    		}
    		    		
    		    		if (foundMethod!=null)
    		    		{
    		    			classPolicy = foundMethod.getParameterTypes()[0];       		    		   		    		
    		    			XposedBridge.log("security method located via method scan - return type "+foundMethod.getReturnType().getName());
    		    		}

    		    		if (classPolicy!=null)
    					{
    		    		
	    		    		XposedHelpers.findAndHookMethod(a, "a", classPolicy, 
	    		    				
	    		    				new XC_MethodReplacement() {
	    						
	    		    			@Override
	    		    			protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
	    		    				XposedBridge.log("method call to g.ahp->a intercepted - returning 0");
	    		    				return 0;
	    		    			}
	    		    		}
	    							//XC_MethodReplacement.returnConstant(Integer.valueOf("0"))
	    	        			);
	    					
	    		    		XposedBridge.log("method hook g.ahp->a hooked");
    					}
    		    		
    				}
    				
    			}
    		  			
    			});
    	}
		
		return a!=null;
		
	}
	
	@Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
    	if (!lpparam.packageName.equals(PACKAGE_EMAIL))
            return;   	
    	
    	XposedBridge.log("Loaded app: " + lpparam.packageName);
   	
    	boolean encryptedStyle = false;
    	
    	try
    	{
    		encryptedStyle = processClass(XposedHelpers.findClass("g.ahp$aX", lpparam.classLoader));
    	}
    	catch(java.lang.Throwable e)
    	{
    		encryptedStyle = false;
    	}
    	
  	
    	if (!encryptedStyle)
    	{
    						
    	
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
}