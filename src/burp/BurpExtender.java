package burp;

import com.camelinc.burp.*;

import java.awt.Component;
import java.util.Iterator;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class BurpExtender implements IBurpExtender, IScannerInsertionPointProvider, IMessageEditorTabFactory {
  private IBurpExtenderCallbacks  callbacks;
  private IExtensionHelpers       helpers;

  private PrintWriter             stdout;
  private PrintWriter             stderr;

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
  {
      // keep a reference to our callbacks object
      this.callbacks = callbacks;

      // obtain an extension helpers object
      helpers = callbacks.getHelpers();

      // set our extension name
      callbacks.setExtensionName("GWTRPC decoder editor");

      // register ourselves as a scanner insertion point provider
    	callbacks.registerScannerInsertionPointProvider(this);

      this.stdout = new PrintWriter(callbacks.getStdout(), true);
      this.stderr = new PrintWriter(callbacks.getStderr(), true);

      // register ourselves as a message editor tab factory
      callbacks.registerMessageEditorTabFactory(this);
  }


  @Override
  public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse)
  {
    IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse.getRequest());


    GWTRPCMessage message = new GWTRPCMessage(baseRequestResponse.getRequest(), helpers);

    // String rpcText = GWTRPCMessage.getRPCText(requestInfo);
    return message.getInsertionPoints(baseRequestResponse);
  }

  @Override
  public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
  {
      this.stdout.println("[BurpExtender] [createNewInstance]");
      // create a new instance of our custom editor tab
      return new GWTRPCInputTab(controller, callbacks, helpers, editable);
  }
}
