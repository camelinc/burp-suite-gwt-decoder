package com.camelinc.burp;


import burp.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.LinkedList;


public class GWTInsertionPoint implements IScannerInsertionPoint
{
  private byte[] baseRequest;
  private String baseValue;

  private String insertionPointPrefix;
  private String insertionPointSuffix;

  private IExtensionHelpers helpers;

  public GWTInsertionPoint(byte[] baseRequest, String rpcString, String dataParameter, IExtensionHelpers helpers)
  {
      this.baseRequest = baseRequest;
      this.helpers     = helpers;
      this.baseValue   = dataParameter;

      dataParameter = "|" + dataParameter + "|"; //find only complete fields

      // parse the location of the input string within the decoded data
      int start = rpcString.indexOf(dataParameter);
      start += 1; // remove seperator
      if (start == -1)
        start = 0;

      int end = start + dataParameter.length();
      end -= 2; // remove seperator
      if (end > rpcString.length())
        end = rpcString.length();

      System.out.println("[GWTInsertionPoint]: \"" + start + "\":\"" + end + ":" + rpcString.length() + "\n");

      insertionPointPrefix = rpcString.substring(0, start);
      insertionPointSuffix = rpcString.substring(end, rpcString.length());

      System.out.println("[GWTInsertionPoint]: \"" + insertionPointPrefix + "\" ___ \"" + insertionPointSuffix + "\n");
  }

  //
  // implement IScannerInsertionPoint
  //

  @Override
  public String getInsertionPointName()
  {
      return "GWT StringTable InsertionPoint";
  }

  @Override
  public String getBaseValue()
  {
      return baseValue;
  }

  @Override
  public byte[] buildRequest(byte[] payload)
  {
    IRequestInfo requestInfo = helpers.analyzeRequest(this.baseRequest);
    List<String> headers = requestInfo.getHeaders();

    // build the raw data using the specified payload
    String newRequestBody = insertionPointPrefix + helpers.bytesToString(payload) + insertionPointSuffix;

    System.out.println("[buildRequest]: \"" + baseValue + "\"  \"" + payload + "\"\n");
    System.out.println("[buildRequest]: \"" + newRequestBody + "\"\n");

    byte[] newRequest = helpers.buildHttpMessage(headers, newRequestBody.getBytes());

    System.out.println("[buildRequest] [newRequest]: \"" + new String(newRequest) + "\"\n");

    return newRequest;
  }

  @Override
  public int[] getPayloadOffsets(byte[] payload)
  {
      // since the payload is being inserted into a serialized data structure, there aren't any offsets
      // into the request where the payload literally appears
      return null;
  }

  @Override
  public byte getInsertionPointType()
  {
      return INS_EXTENSION_PROVIDED;
  }
}
