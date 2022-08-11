package com.saxobank.datahub.oauth.oauthbearer;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.Objects;

public class Utils {

    private static final Logger log = LoggerFactory.getLogger(Utils.class);

    protected static Map<String, Object> handleAADResponse(InputStream inputStream) throws IOException {
        Map<String, Object> result = null;
        try {

            log.debug("Starting to convert HTTP JSON response into a key value pairs.");

            log.info("Validate method parameters.");
            Objects.requireNonNull(inputStream);

            log.debug("Read the HTTP response into a string.");
            try (BufferedReader in = new BufferedReader(new InputStreamReader(inputStream))) {
                String inputLine;
                StringBuffer response = new StringBuffer();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                String jsonResponse = response.toString();

                log.debug("Parse JSON string into a key value pairs.");
                ObjectMapper objectMapper = new ObjectMapper();
                result = objectMapper.readValue(jsonResponse, new TypeReference<Map<String, Object>>() {
                });
            }
        }
        catch (NullPointerException npe) {
            log.error("Error converting HTTP JSON response, null pointer exception.", npe);
            throw npe;
        } catch (IOException ex) {
            log.error("Error converting HTTP JSON response into a key value pairs.", ex);
            throw ex;
        }
        finally {
            log.debug("Finished converting HTTP JSON response into a key value pairs");
        }
        return result;
    }
}
