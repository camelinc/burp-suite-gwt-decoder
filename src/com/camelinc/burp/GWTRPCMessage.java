package com.camelinc.burp;

import burp.*;
import com.camelinc.burp.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.LinkedList;

import java.util.Iterator;

public class GWTRPCMessage {

    private static final int STRING_TABLE_OFFSET = 3;

    protected class GWTRPCParameter
    {
        protected int index;
        protected String value;
        protected String type;

        public GWTRPCParameter(int index, String value)
        {
            this.index = index;
            this.value = value;
        }
        public GWTRPCParameter(int index, String value, String type)
        {
            this.index = index;
            this.value = value;
            this.type = type;
        }
    }

    // protected GWTRPCPayload payload;

    protected String rpcStringRaw;
    private final ArrayList<String> paramsList = new ArrayList<String>();

    private final ArrayList<String> tokenList = new ArrayList<String>();
    private int tokenListIndex;
    private String[] stringTable;
    public static final char RPC_SEPARATOR_CHAR = '|';

    private int flags;
    private int version;
    private String moduleBaseURL;
    private String strongName;
    private String serviceMethodName;
    private String RPCToken;
    private int paramCount;

    private byte[] baseRequest;
    private IExtensionHelpers helpers;
    // http://grepcode.com/file/repo1.maven.org/maven2/com.google.gwt/gwt-user/2.1.0/com/google/gwt/user/server/rpc/RPC.java#RPC.decodeRequest%28String%2Cjava.lang.Class%2Ccom.google.gwt.user.server.rpc.SerializationPolicyProvider%29
    // http://grepcode.com/file/repo1.maven.org/maven2/com.google.gwt/gwt-user/2.1.0/com/google/gwt/user/server/rpc/impl/ServerSerializationStreamReader.java#ServerSerializationStreamReader.prepareToRead%28String%29
    public GWTRPCMessage(byte[] baseRequest, String rpcString, IExtensionHelpers helpers)
    {
        this.baseRequest  = baseRequest;
        this.helpers      = helpers;

        this.rpcStringRaw = rpcString;
        this.parseString(rpcString);

        // this.stdout.println("[GWTRPCInputTab]");
    }
    public GWTRPCMessage(byte[] baseRequest, IExtensionHelpers helpers)
    {
        this.baseRequest  = baseRequest;
        this.helpers      = helpers;

        this.rpcStringRaw = getRPCText(helpers.analyzeRequest(baseRequest));
        this.parseString(this.rpcStringRaw);

        // this.stdout.println("[GWTRPCInputTab]");
    }
    public void prepareToRead(String encodedTokens) throws Exception
    {
        tokenList.clear();
        tokenListIndex = 0;
        stringTable = null;

        int idx = 0, nextIdx;
        while (-1 != (nextIdx = encodedTokens.indexOf(RPC_SEPARATOR_CHAR, idx))) {
          String current = encodedTokens.substring(idx, nextIdx);
          tokenList.add(current);
          idx = nextIdx + 1;
        }
        //old format

        //super
        setVersion(readInt());
        setFlags(readInt());

        // TODO: Check the RPC version number sent by the client

        // Read the type name table
        deserializeStringTable();

        // Write the serialization policy info
        moduleBaseURL = readString();
        strongName = readString();
    }

    private void deserializeStringTable() throws Exception
    {
      int typeNameCount = readInt();
      BoundedList<String> buffer = new BoundedList<String>(String.class, typeNameCount);

      for (int typeNameIndex = 0; typeNameIndex < typeNameCount; ++typeNameIndex)
      {
        String str = extract();
        buffer.add(str);
      }
      if (buffer.size() != buffer.getExpectedSize()) {
        throw new Exception("Expected " + buffer.getExpectedSize()
            + " string table elements; received " + buffer.size());
      }

      stringTable = buffer.toArray(new String[buffer.getExpectedSize()]);
    }
    private void deserializeParams() throws Exception
    {
      int index;
      for (int typeNameIndex = 0; typeNameIndex < this.tokenList.size() - 2 - this.stringTable.length; ++typeNameIndex)
      {
        String str = extract();

        try {
          index = Integer.parseInt(str);
        } catch (NumberFormatException e) {
          paramsList.add(str);
          continue;
        }

        // FIXME: Parameter 0-4 not possible
          // probably boolean/Integer

        if (index >= 1 && index <= 4) { // index 0-4 not possible
          str = str;
        } else if (index <= stringTable.length) {
          str = getString(index);

          // TODO: Identify d/j/b/k at the end of String
            // might be base64 encoded numbers
        }
        //FIXME: utilize GWTRPCPayload
        paramsList.add(str);
      }
    }

    private void parseString(String rpcString)
    {
      try {
        prepareToRead(rpcString);
      }catch (Exception e) {
        System.out.println("ERROR1: " + e);
      }

      // check if classes exists on the server

      serviceMethodName = readString();
      RPCToken = readString();

      paramCount = readInt();
      if (paramCount > tokenList.size())
      {
        System.out.println("Invalid number of parameters");
      }
      // Class<?>[] parameterTypes = new Class[paramCount];
      // FIXME: create mockup class
      // Object[] parameterValues = new Object[parameterTypes.length];

      if (paramCount > 0)
      {
        try {
          deserializeParams();
        }catch (Exception e) {
          System.out.println("ERROR2: " + e);
        }
      }
    }
    public String toString() {
      String out = "";

      out += rpcStringRaw;

      out += "\n\n";
      out += "Version: " + this.version + "\nFlags: " + this.flags;

      out += "\n\n";
      // for (String s: this.stringTable)
      for (int i = 0; i < stringTable.length; i++ ) {
          out += i+1 + ": " + stringTable[i] + "\n";
      }

      out += "\n\n";
      out += "Params: " + this.paramCount + "\n";
      for (int i = 0; i < paramsList.size(); i++ ) {
          out += i+1 + ": " + paramsList.get(i) + "\n";
      }
      return out;

      //return rpcStringRaw + "\n\n" + this.header + "\n\n" + this.stringTable + "\n\n" + this.payload;
    }

    private String extract() throws IndexOutOfBoundsException {
      try {
        return tokenList.get(tokenListIndex++);
      } catch (IndexOutOfBoundsException e) {
        throw e;
      }
    }
    public String readString() throws IndexOutOfBoundsException {
      return getString(readInt());
    }
    protected String getString(int index) {
      if (index == 0) {
        return null;
      }
      // index is 1-based
      assert (index > 0);
      assert (index <= stringTable.length);
      return stringTable[index - 1];
    }
    public int readInt() throws NumberFormatException {
      String value = extract();
      try {
        return Integer.parseInt(value);
      } catch (NumberFormatException e) {
        throw e;
      }
    }
    public final void setFlags(int flags) {
      this.flags = flags;
    }
    protected final void setVersion(int version) {
      this.version = version;
    }

    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse)
    {
      return this.getInsertionPoints();
    }
    private List<IScannerInsertionPoint> getInsertionPoints()
    {
      // if the parameter is present, add a single custom insertion point for it
      List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();

      // for (String s: this.stringTable)
      for (int i = 5; i < stringTable.length; i++ ) {
          System.out.println(i+1 + ": " + stringTable[i] + "\n");

          // https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html#makeScannerInsertionPoint(java.lang.String,%20byte[],%20int,%20int)
          // this.helpers.makeScannerInsertionPoint();
          try {
          insertionPoints.add(new GWTInsertionPoint(this.baseRequest, this.rpcStringRaw, stringTable[i], this.helpers));
        }catch (Exception e) {
          System.out.println(e);
        }
      }

      return insertionPoints;
    }

    public String getRPCText(IRequestInfo requestInfo) {
      String rpcText = "";

      List<IParameter> params = requestInfo.getParameters();

      for (Iterator<IParameter> iter = params.iterator(); iter.hasNext(); ) {
        IParameter param = iter.next();

        if (param.getType() == IParameter.PARAM_BODY)
        {
          rpcText = param.getName();
          return rpcText;
        }
      }
      return null;
    }


  /**
   * Used to accumulate elements while deserializing array types. The generic
   * type of the BoundedList will vary from the component type of the array it
   * is intended to create when the array is of a primitive type.
   *
   * @param <T> The type of object used to hold the data in the buffer
   */
  private static class BoundedList<T> extends LinkedList<T> {
    private final Class<?> componentType;
    private final int expectedSize;

    public BoundedList(Class<?> componentType, int expectedSize) {
      this.componentType = componentType;
      this.expectedSize = expectedSize;
    }

    public boolean add(T o) {
      assert size() < getExpectedSize();
      return super.add(o);
    }

    public Class<?> getComponentType() {
      return componentType;
    }

    public int getExpectedSize() {
      return expectedSize;
    }
  }


  protected class GWTRPCPayload
  {
      protected int payloadOffset;
      protected int payloadSize;
      protected int length;
      protected int parameterCount;

      protected String[] payload;
      protected List<GWTRPCParameter> parameters = new ArrayList<GWTRPCParameter>();

      public GWTRPCPayload(String rpcString, ArrayList<String> stringTable)
      {
          String[] tmp;
          tmp = rpcString.split("\\|");

          this.payloadOffset  = stringTable.size() + 3;
          this.payloadSize    = tmp.length - payloadOffset;
          this.length         = tmp.length - payloadOffset;
          this.parameterCount = 0;

          this.payload = new String[this.payloadSize];

          int index;
          String idx, value, type;
          // for (int i = this.payloadOffset; i < this.payloadOffset + this.payloadSize; i++) {
          for (int i = 0; i < this.payloadSize; i++) {

              idx = tmp[this.payloadOffset + i];

              try {
                  index = Integer.parseInt(idx);
              }catch (NumberFormatException nfe) {
                  value = idx;
                  index = 0;
              }

              if (i < 4)
              {
                  value = resolvePayloadIndex(tmp, index);
                  this.parameters.add(new GWTRPCParameter(index, value));
              }else if (i == 4)
              {
                  this.parameterCount = index;
                  this.parameters.add(new GWTRPCParameter(index, "0"));
              }else if (i > 4 && i - 4 < this.parameterCount * 2)
              {
                  value = resolvePayloadIndex(tmp, index);
                  i++;
                  // int index2 = Integer.parseInt(tmp[i]);
                  // type = value;
                  if (index == 0)
                  {
                      type = "";
                      this.parameters.add(new GWTRPCParameter(index, value));
                  }else
                  {
                      int index2;

                      idx = tmp[this.payloadOffset + i];
                      try {
                          index2 = Integer.parseInt(idx);
                          type = value;
                          value = resolvePayloadIndex(tmp, index2);
                      }catch (NumberFormatException nfe) {
                          type = idx;
                          index2 = 0;
                      }

                      this.parameters.add(new GWTRPCParameter(index, value, type));
                  }
              }else{
                  value = idx;
                  // index = 0;
                  if (index == 0 )
                  {
                      value = null;
                  }else if(2+index < tmp.length) //FIXME: Stringtable length
                  {
                      value = resolvePayloadIndex(tmp, index);
                  }

                  this.parameters.add(new GWTRPCParameter(index, value));
              }
          }
      }

      private String resolvePayloadIndex(String[] tmp, int index)
      {
          if (index <= 0) {
            return "0";
          }

          return tmp[2 + index];
      }

      public String toString() {
          GWTRPCParameter p;
          String out = "";

          p = this.parameters.get(0);
          out += "BaseURL:     " + p.index + ": " + p.value + "\n";
          p = this.parameters.get(1);
          out += "StrongName:  " + p.index + ": " + p.value + "\n";
          p = this.parameters.get(2);
          out += "RPCToken:    " + p.index + ": " + p.value + "\n";
          p = this.parameters.get(3);
          out += "ServiceName: " + p.index + ": " + p.value + "\n";
          p = this.parameters.get(4);
          out += "Parameters:  " + p.index + "\n";

          if (this.parameters.size() > 5 || this.parameters.get(4).index != 0)
          {
              for (GWTRPCParameter p2: this.parameters.subList(5, 5+this.parameterCount))
              {
                  if (p2.type != null)
                  {
                      out += "\t" + p2.index + ": " + p2.value + " (" +p2.type +")\n";
                  }else
                  {
                      out += "\t" + p2.index + ": " + p2.value + "\n";
                  }
              }
          }

          if (this.parameters.size() >= 5 + 1 + this.parameterCount)
          {
              out += "\n";
              for (GWTRPCParameter p2: this.parameters.subList(5+1+this.parameterCount, this.parameters.size()))
              {
                  out += "\t" + p2.index + ": " + p2.value + "\n";
              }
          }
          return out;
      }
  }
}
