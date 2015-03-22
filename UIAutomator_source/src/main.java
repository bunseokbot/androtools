
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import com.android.uiautomator.core.*;
import com.android.uiautomator.testrunner.UiAutomatorTestCase;

public class main extends UiAutomatorTestCase {
	
	//Enable Device Admin
	public void enableDeviceAdmin() throws UiObjectNotFoundException {
		UiObject activateBtn = new UiObject(new UiSelector().text("Activate").className("android.widget.Button")); //UiObject set to Activate Button
		if(activateBtn.exists()) {
			activateBtn.click();
		}
	}
	
	//Ready for Analysis
	public void readyForAnalysis() throws UiObjectNotFoundException {
		getUiDevice().pressHome(); //press home button
        UiObject loadallapps = new UiObject(new UiSelector().description("Apps"));
        loadallapps.clickAndWaitForNewWindow();
	}
	
	//Uninstall App
	public void rapidUninstall() throws Exception {
		String packname = getParams().getString("packname");
		String preUninstall = runADBCommand("adb uninstall " + packname);
		if(preUninstall.contains("Failure")) {
			disableDeviceAdmin();
			String reUninstall = runADBCommand("adb uninstall " + packname);
		}
	}
	
	//run adbcommmand
	public String runADBCommand(String adbCommand) throws IOException {
		String returnValue = "", line;
		InputStream inStream = null;
		try {
		    Process process = Runtime.getRuntime().exec(adbCommand);
		    inStream = process.getInputStream();
		    BufferedReader brCleanUp = new BufferedReader(
		                                               new InputStreamReader(inStream));
		    while ((line = brCleanUp.readLine()) != null) {
		         returnValue = returnValue + line + "\n";
		    }
		    brCleanUp.close();
		    try {
		         process.waitFor();
		    } catch (InterruptedException e) {
		         e.printStackTrace();
		    }
		  } catch (Exception e) {
		    e.printStackTrace();
		  }
		  System.out.println(returnValue);
		  return returnValue;
	}
	
	public void captureScreenshot(String filehash) throws Exception {
		String capture = runADBCommand("adb shell screencap -p /sdcard/screenshot.png");
		
	}

	// param as process id -> a.k.a pid
	//automated action, button analysis, deviceadmin check
	public void automatedAction() throws Exception {
		String packname = getParams().getString("packname");
		enableDeviceAdmin();
		try {
			UiObject anyBtn = new UiObject(new UiSelector().className("android.widget.Button")); //button detect in screen!
			if(anyBtn.exists()) { //if any button exist? 
				anyBtn.click();  //click the button!!!
			}
			Thread.sleep(5000); //sleep 5 second
			//disableDeviceAdmin(packname); //disable deviceadmin as fast as possible 
		} catch(Exception e) {
			//System.out.println(e);//Exception?! -> fuck!
		}
		getUiDevice().pressHome(); //press home button
	}
	
	//disable deviceadmin
	public void disableDeviceAdmin() throws Exception {
		String packname = getParams().getString("packname");
		String gotoDeviceAdmin = runADBCommand("adb shell am start -S \'com.android.settings/com.android.settings.DeviceAdminSettings\'");
		UiObject textview = new UiObject(new UiSelector().text("No available device administrators").className("android.widget.TextView"));
		if(textview.exists()) {
			getUiDevice().pressHome();
		} else {
			UiScrollable listview = new UiScrollable(new UiSelector().className("android.widget.ListView"));
			int count = listview.getChildCount() - 1;
			String pid = runADBCommand("adb shell ps | grep " + packname + " | awk '{print $2}'"); //get pid
			String kill = runADBCommand("kill " + pid); //kill malware process!
			listview.getChild(new UiSelector().clickable(true).index(count)).clickAndWaitForNewWindow();
			UiObject deactivateBtn = new UiObject(new UiSelector().text("Deactivate").className("android.widget.Button")); //UiObject set to Activate Button
			if(deactivateBtn.exists()) {
				deactivateBtn.click();
				UiObject clickOk = new UiObject(new UiSelector().text("OK"));
				if(clickOk.exists()) {
					clickOk.click();
					getUiDevice().pressHome();
				}
			}
		}
		String uninstall = runADBCommand("adb uninstall " + packname);
		getUiDevice().pressHome();
	}
}
