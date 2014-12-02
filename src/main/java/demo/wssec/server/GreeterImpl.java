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

package demo.wssec.server;

import demo.wssec.common.Signutil;
import fi.bxd.xmldata.ApplicationRequest;
import org.apache.cxf.hello_world_soap_http.Greeter;
import org.apache.cxf.hello_world_soap_http.types.Request;
import org.w3c.dom.Document;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.util.logging.Logger;

@javax.jws.WebService(serviceName = "GreeterService",
            portName = "GreeterPort",
            endpointInterface = "org.apache.cxf.hello_world_soap_http.Greeter",
            wsdlLocation = "file:./wsdl/hello_world_wssec.wsdl",
            targetNamespace = "http://cxf.apache.org/hello_world_soap_http")
                  
public class GreeterImpl implements Greeter {

    private static final Logger LOG = 
        Logger.getLogger(GreeterImpl.class.getPackage().getName());

    private JAXBContext context;
    private TransformerFactory transformerFactory;

    Signutil signutil;
    private final DocumentBuilderFactory documentBuilderFactory;


    public GreeterImpl() throws Exception {
        context = JAXBContext.newInstance(ApplicationRequest.class);
        transformerFactory = TransformerFactory.newInstance();

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(getClass().getResourceAsStream("/keystore/nordea.jks"), null);

        documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);

        signutil = new Signutil(ks);
    }

    @Override
    public boolean sendPayload(Request in) {
        LOG.info("Executing operation sendPayload");

        try {
            Document doc = documentBuilderFactory.newDocumentBuilder().newDocument();
            DOMResult result = new DOMResult(doc);
            transformerFactory.newTransformer().transform(new StreamSource(new ByteArrayInputStream(in.getPayload())), result);
            boolean valid = signutil.validate(doc, "11111111", true);

            Unmarshaller um = context.createUnmarshaller();
            ApplicationRequest request = (ApplicationRequest) um.unmarshal(result.getNode().getFirstChild());
            String content = request.getContent();

            System.out.println("Received content: " + content);
            System.out.println("Payload signature valid: " + valid);
            return valid;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
