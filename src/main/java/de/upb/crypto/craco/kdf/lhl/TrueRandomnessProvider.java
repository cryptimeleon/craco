package de.upb.crypto.craco.kdf.lhl;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.SecureRandom;

/**
 * Provides truly random bits via an API-call to RANDOM.ORG
 *
 * @author Mirko Jürgens
 */
public class TrueRandomnessProvider {

    private static String invoke_url = "https://api.random.org/json-rpc/1/invoke";

    private static String api_key = "517ceadc-2d34-405a-80d4-cc080b1c1192";

    public static String getTrulyRandomNumbers(int bitLength) {
        String toReturn = null;
        try {
            toReturn = cummultativeAPICall(bitLength);
        } catch (IOException | ParseException e) {
            byte[] b = new byte[bitLength / 8];
            new SecureRandom().nextBytes(b);
            StringBuilder builder = new StringBuilder();
            for (byte byt : b) {
                builder.append(Integer.toBinaryString((byt + 256) % 256));
            }
            toReturn = builder.toString();
        }
        return toReturn;
    }

    private static String cummultativeAPICall(int bitLength) throws IOException, ParseException {
        StringBuilder bos = new StringBuilder();
        while (bitLength > 30) {
            String bytes = makeAPICall(30);
            bos.append(bytes);
            bitLength -= 30;
        }
        if (bitLength > 0) {
            String bytes = makeAPICall(bitLength);
            bos.append(bytes);
        }
        return bos.toString();
    }

    /**
     * Copyright by https://github.com/RandomOrg/JSON-RPC-Java
     *
     * @param bitLength
     * @return
     * @throws IOException
     * @throws ParseException
     */
    @SuppressWarnings("unchecked")
    private static String makeAPICall(int bitLength) throws IOException, ParseException {
        JSONObject json = new JSONObject();
        json.put("jsonrpc", "2.0");
        json.put("method", "generateIntegers");
        JSONObject params = new JSONObject();
        params.put("apiKey", api_key);
        params.put("n", "1");
        params.put("min", "-" + ((long) Math.pow(2, ((long) bitLength) - 1)));
        params.put("max", "" + ((long) Math.pow(2, ((long) bitLength) - 1) - 1));

        HttpsURLConnection con = (HttpsURLConnection) new URL(invoke_url).openConnection();
        con.setConnectTimeout(200);
        json.put("params", params);
        json.put("id", "1");
        // headers
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");

        // send JSON
        con.setDoOutput(true);
        DataOutputStream dos = new DataOutputStream(con.getOutputStream());
        dos.writeBytes(json.toJSONString());
        dos.flush();
        dos.close();

        // check response
        int responseCode = con.getResponseCode();

        // return JSON...
        if (!(responseCode == HttpsURLConnection.HTTP_OK)) {
            throw new IOException("Failed to retrieve random bits");
        }
        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        if ((response.toString().contains("error"))) {
            throw new IOException("Failed to retrieve random bits");
        }

        JSONParser parser = new JSONParser();
        JSONObject resp = (JSONObject) parser.parse(response.toString());
        JSONObject result = (JSONObject) resp.get("result");
        JSONObject random = (JSONObject) result.get("random");
        JSONArray dataArray = (JSONArray) random.get("data");
        Long randomInt = (long) dataArray.get(0);
        if (randomInt < 0) {
            return Long.toBinaryString((long) dataArray.get(0)).substring(64 - bitLength);
        } else {
            String signedLong = Long.toBinaryString((long) dataArray.get(0));
            int missingZeros = bitLength - signedLong.length();
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < missingZeros; i++) {
                builder.append("0");
            }
            builder.append(signedLong);
            return builder.toString();
        }
    }

}
