package com.camelinc.burp;

import burp.*;
import com.codemagi.parsers.GWTParser;

import java.awt.Component;
import java.util.Iterator;

import java.io.PrintWriter;
import java.io.StringWriter;

public class GWTRPCInputTab implements IMessageEditorTab
{
    protected static PrintWriter stderr;
    protected static PrintWriter stdout;

    protected IBurpExtenderCallbacks callbacks;
    protected IExtensionHelpers helpers;

    private boolean editable;
    private ITextEditor txtInput;
    private byte[] currentMessage;

    public GWTRPCInputTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks,
                     IExtensionHelpers helpers, boolean editable)
    {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.stdout.println("[GWTRPCInputTab] [_init_]");

        this.callbacks = callbacks;
        this.helpers = helpers;

        this.editable = editable;

        // create an instance of Burp's text editor, to display our deserialized data
        txtInput = callbacks.createTextEditor();
        txtInput.setEditable(editable);

        this.stdout.println("[GWTRPCInputTab]");
    }

    @Override
    public String getTabCaption()
    {
        return "GWT RPC";
    }

    @Override
    public Component getUiComponent()
    {
        return txtInput.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest)
    {
        this.stdout.println("[GWTRPCInputTab] [isEnabled]");

        IRequestInfo requestInfo;
        java.util.List<java.lang.String> headers;

        Boolean checkContentType;
        Boolean checkGWTHeader;

        requestInfo = helpers.analyzeRequest(content);
        headers = requestInfo.getHeaders();

        checkContentType = false;
        checkGWTHeader   = false;

        for (Iterator<java.lang.String> iter = headers.iterator(); iter.hasNext(); ) {
            java.lang.String header = iter.next();

            if (header.contains("X-GWT-Module-Base"))
            {
                checkGWTHeader = true;
            }

            if (header.contains("Content-Type: text/x-gwt-rpc; charset=utf-8"))
            {
                checkContentType = true;
            }
        }

        if (checkContentType && checkGWTHeader)
        {
            this.stdout.println("[GWTRPCInputTab] [isEnabled] true");
            return true;
        }
        return false;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest)
    {
        this.stdout.println("[GWTRPCInputTab] [setMessage]");

        if (content == null)
        {
            // clear our display
            txtInput.setText(null);
            txtInput.setEditable(false);
        }
        else
        {
            IRequestInfo requestInfo;
            java.util.List<IParameter> params;
            java.lang.String rpcText;
            GWTRPCMessage message;

            try {
                requestInfo = helpers.analyzeRequest(content);
                params      = requestInfo.getParameters();

                this.stdout.println("[GWTRPCInputTab] [setMessage]");

                rpcText = "";
                for (Iterator<IParameter> iter = params.iterator(); iter.hasNext(); ) {
                    IParameter param = iter.next();

                    if (param.getType() == IParameter.PARAM_BODY)
                    {
                        rpcText = param.getName();
                        break;
                    }
                }

                message = new GWTRPCMessage(content, rpcText, helpers);
              	// GWTParser parser = new GWTParser();
              	// parser.parse(rpcText);

                // deserialize the parameter value
                txtInput.setText(message.toString().getBytes());
                txtInput.setEditable(editable);
            } catch (Exception e) {
                this.txtInput.setText(this.helpers.stringToBytes("\n--- FAILURE ---\n\nSee output in extension tab for details"));
                this.txtInput.setEditable(false);
                this.stderr.println(getStackTrace(e));
            }
        }

        // remember the displayed content
        currentMessage = content;
    }

    @Override
    public byte[] getMessage()
    {
        this.stdout.println("[GWTRPCInputTab] [getMessage]");
        if (true)
        {
            return currentMessage;
        }

        // determine whether the user modified the deserialized data
        if (txtInput.isTextModified())
        {
            // reserialize the data
            byte[] text = txtInput.getText();
            String input = helpers.urlEncode(helpers.base64Encode(text));

            // update the request with the new parameter value
            return helpers.updateParameter(currentMessage, helpers.buildParameter("data", input, IParameter.PARAM_BODY));
        }
        else return currentMessage;
    }
    @Override
    public boolean isModified()
    {
        this.stdout.println("[GWTRPCInputTab] [isModified]");
        return txtInput.isTextModified();
    }

    @Override
    public byte[] getSelectedData()
    {
        this.stdout.println("[GWTRPCInputTab] [getSelectedData]");
        return txtInput.getSelectedText();
    }

    protected static String getStackTrace(Throwable t) {
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter, true);
        t.printStackTrace(printWriter);
        printWriter.flush();
        stringWriter.flush();

        return stringWriter.toString();
    }
}
