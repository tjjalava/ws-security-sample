/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package demo.wssec.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.URL;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import demo.wssec.common.Signutil;
import fi.bxd.xmldata.ApplicationRequest;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.hello_world_soap_http.Greeter;
import org.apache.cxf.hello_world_soap_http.GreeterService;
import org.apache.cxf.hello_world_soap_http.types.Application;
import org.apache.cxf.ws.security.wss4j.DefaultCryptoCoverageChecker;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.w3c.dom.Document;

import javax.xml.bind.JAXBContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * A DOM-based client
 */
public final class Client {

    private static final String WSSE_NS 
        = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSU_NS
        = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    private Client() {

    }

    public static void main(String args[]) throws Exception {
        try {

            SpringBusFactory bf = new SpringBusFactory();
            URL busFile = Client.class.getResource("wssec.xml");
            Bus bus = bf.createBus(busFile.toString());
            BusFactory.setDefaultBus(bus);

            Map<String, Object> outProps = new HashMap<String, Object>();
            outProps.put("action", "Timestamp Signature");

            outProps.put("passwordType", "PasswordDigest");

            outProps.put("user", "abcd");
            outProps.put("signatureUser", "clientx509v1");

            outProps.put("passwordCallbackClass", "demo.wssec.client.UTPasswordCallback");

            outProps.put("signaturePropFile", "etc/Client_Sign.properties");
            outProps.put("signatureKeyIdentifier", "DirectReference");
            outProps.put("signatureParts",
                         "{Element}{" + WSU_NS + "}Timestamp;"
                         + "{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;"
                         + "{}{http://www.w3.org/2005/08/addressing}ReplyTo;");

            outProps.put("signatureAlgorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");


            Map<String, Object> inProps = new HashMap<String, Object>();

            inProps.put("action", "Timestamp Signature");
            inProps.put("passwordType", "PasswordText");
            inProps.put("passwordCallbackClass", "demo.wssec.client.UTPasswordCallback");


            inProps.put("signaturePropFile", "etc/Client_Encrypt.properties");
            inProps.put("signatureKeyIdentifier", "DirectReference");

            inProps.put("signatureAlgorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");


            // Check to make sure that the SOAP Body and Timestamp were signed,
            // and that the SOAP Body was encrypted
            DefaultCryptoCoverageChecker coverageChecker = new DefaultCryptoCoverageChecker();
            coverageChecker.setSignBody(true);
            coverageChecker.setEncryptUsernameToken(false);
            coverageChecker.setSignTimestamp(true);
            coverageChecker.setEncryptBody(false);

            GreeterService service = new GreeterService();
            Greeter port = service.getGreeterPort();
            org.apache.cxf.endpoint.Client client = ClientProxy.getClient(port);
            client.getInInterceptors().add(new WSS4JInInterceptor(inProps));
            client.getOutInterceptors().add(new WSS4JOutInterceptor(outProps));
            client.getInInterceptors().add(coverageChecker);
            

            JAXBContext context = JAXBContext.newInstance(ApplicationRequest.class);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(Client.class.getResourceAsStream("/keystore/nordea.jks"), null);

            Signutil signutil = new Signutil(keyStore);
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);

            for (int i = 0; i < 4; i++) {
                Application payload = new Application();
                ApplicationRequest request = new ApplicationRequest();
                request.setContent("This is content " + i);

                Document doc = documentBuilderFactory.newDocumentBuilder().newDocument();
                DOMResult result = new DOMResult(doc);
                context.createMarshaller().marshal(request, result);
                DOMResult signed = signutil.sign(result, "11111111", "WSNDEA1234");

                System.out.println("Signature valid: " + signutil.validate(doc, "11111111"));

                ByteArrayOutputStream out = new ByteArrayOutputStream();
                transformer.transform(new DOMSource(signed.getNode().getFirstChild()), new StreamResult(out));
                payload.setPayload(out.toByteArray());

                Application response = port.sendPayload(payload);

                ApplicationRequest resp = (ApplicationRequest) context.createUnmarshaller().unmarshal(new ByteArrayInputStream(response.getPayload()));

                System.out.println("Got response: " + resp.getContent());
            }

            // allow asynchronous resends to occur
            Thread.sleep(/*10 * */1000);

            if (port instanceof Closeable) {
                ((Closeable)port).close();
            }

            bus.shutdown(true);

        } catch (UndeclaredThrowableException ex) {
            ex.getUndeclaredThrowable().printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            System.exit(0);
        }
    }
}
