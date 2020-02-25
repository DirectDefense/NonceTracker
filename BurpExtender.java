package burp;

import java.io.PrintWriter;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IHttpListener, 
        IExtensionStateListener
{
    //private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private IExtensionHelpers helpers; 
    //Tracker Lists
	private LinkedList<String> trackerNonce = new LinkedList<String>();
	private LinkedList<String> trackerPage = new LinkedList<String>();
	
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Nonce Tracker");
        
        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        
        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
        
        // register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(this);
    }

    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
    	//Patterns to extract NONCE VALUE
    	Pattern requestNoncePattern = Pattern.compile("\\b/[\\w-_&=./].*nonce=[\\w]*");
    	Pattern responseNoncePattern = Pattern.compile("[a-zA-Z0-9-_\\?;=&\\./]*nonce=[a-z0-9]*");
    	//Pattern replaceNoncePattern = Pattern.compile("(?<=nonce=)[\\w]*(?=\\sHTTP)");    	
    	
    	//If it is a request, find nonce value and determine if it needs to be changed to stored values
    	if(messageIsRequest){
	    	//Temporary Handling Parameters
	    	String rqNonceFound = "";
	    	String rqSentNonce = "";
	    	String rqPage = "";
	    	String rqFullPage = "";
	    	int rqNewNonceIndex = -1;
	    	//Get the request URL
	    	IRequestInfo rqInfo = helpers.analyzeRequest(messageInfo);
	    	String getURL = rqInfo.getUrl().toString();
	    	//Get Current Request Loaded 
	    	String oldRequest = new String(messageInfo.getRequest());
	    	
	    	//Search the URL for NONCE
	    	Matcher match = requestNoncePattern.matcher(getURL);
	    	//If Page Request Contains NONCE
			if(match.find()){
				rqNonceFound = match.group(0);
				//Format Page and NONCE values to be compared
				String[] reqSplit = rqNonceFound.split("(\\?|&|&amp;)nonce=");
				rqFullPage = reqSplit[0];
				//Remove Directory Rewrite
				rqPage = rqFullPage.replaceAll("\\/foo\\/", "");
		    	rqSentNonce = reqSplit[1].toString();
		    	rqNewNonceIndex = trackerPage.indexOf(rqPage);
		    	//If Page NONCE is stored in tracker
		    	if(rqNewNonceIndex > -1){
		    		String tempStoreNonce = trackerNonce.get(rqNewNonceIndex);
		    		//If new page request does not match stored NONCE
		    		if(!tempStoreNonce.equals(rqSentNonce)){
		    			stdout.println("Switching nonce on page: "+ rqPage +" Sent Nonce: "+rqSentNonce +" New Nonce: "+tempStoreNonce );
		    			//Perform a replace with new value
		    			String newRequest = oldRequest.replaceFirst("(?<=nonce=)[\\w]*(?=\\sHTTP)", tempStoreNonce);
		    			//Convert new request to bytes and send it off.
		    			byte[] newRequestBytes = newRequest.getBytes();
		    			messageInfo.setRequest(newRequestBytes);
		    		}
		    	}
			}
	    	
    	}else{ // Otherwise it is a response, parse response for all new nonce values, either add them if they are new or update previous values
    		//Get Response
    		String response = new String(messageInfo.getResponse());
    		//Search Response for the nonce pattern
    		Matcher match = responseNoncePattern.matcher(response);
	    	//If Page Uses Nonce collect them all
			while(match.find()){
				//Temporary Values
				int rpPageIndex = -1;
				String rpTrackerPage = "";
				String rpTrackerNonce = "";
				String rpFound = match.group();
				String[] reqSplit = rpFound.split("(\\?|&|&amp;)nonce=");
				
				//Search for page to determine if add or update
				rpTrackerPage = reqSplit[0].toString();
				rpPageIndex = trackerPage.indexOf(rpTrackerPage);
				rpTrackerNonce = reqSplit[1].toString();
				
				//If Found Update Old Value
				if(rpPageIndex > -1){
					String tempStoredTrackerNonce = trackerNonce.get(rpPageIndex);
					if(!tempStoredTrackerNonce.equals(rpTrackerNonce)){
						trackerNonce.set(rpPageIndex, rpTrackerNonce);
						stdout.println("Tracker Updated Page: "+rpTrackerPage+" Tracker Updated Nonce: "+rpTrackerNonce+" From: "+tempStoredTrackerNonce);
					}
				}else{ //If Not Found Add it to the list as a new tracker
					trackerPage.add(rpTrackerPage);
					trackerNonce.add(rpTrackerNonce);
					stdout.println("Tracker Add Page: "+rpTrackerPage+ " Tracker Add Nonce: "+rpTrackerNonce);
				}
			}
				
    	}
 
    }
    
    @Override
    public void extensionUnloaded()
    {
    	trackerNonce.clear();
    	trackerPage.clear();
        stdout.println("Extension was unloaded and tracker was cleared");
    }
}



