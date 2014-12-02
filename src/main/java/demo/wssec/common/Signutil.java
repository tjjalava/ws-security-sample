package demo.wssec.common;

import com.google.common.collect.Lists;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 * @author jalavat
 * @since 1.12.14
 */
public class Signutil {

    private static final String PROVIDER_NAME = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
    private final XMLSignatureFactory xmlSignatureFactory;

    private final KeyInfoFactory keyInfoFactory;
    private final TransformerFactory transformerFactory;

    private final KeyStore keyStore;

    public Signutil(KeyStore keyStore) throws Exception {
        this.keyStore = keyStore;
        xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(PROVIDER_NAME).newInstance());
        keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        transformerFactory = TransformerFactory.newInstance();
    }

    public DOMResult sign(DOMResult applicationRequest, String alias, String password) throws Exception {
        try {
            X509Certificate certificate = (X509Certificate) (keyStore.getCertificate(alias));
            X509Data x509Data = keyInfoFactory.newX509Data(
                    Lists.newArrayList(
                            keyInfoFactory.newX509IssuerSerial(certificate.getIssuerX500Principal().getName(), certificate.getSerialNumber()),
                            certificate
                    )
            );
            KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Lists.newArrayList(x509Data));
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
            Reference reference = xmlSignatureFactory.newReference(
                    "", xmlSignatureFactory.newDigestMethod(DigestMethod.SHA1, null),
                    Lists.newArrayList(xmlSignatureFactory.newTransform(Transform.ENVELOPED, (XMLStructure) null)), null, null
            );
            Node document = applicationRequest.getNode().getFirstChild();

            DOMSignContext dsc = new DOMSignContext(privateKey, document);
            SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(
                    xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                    xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                    Lists.newArrayList(reference)
            );

            XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
            signature.sign(dsc);

            DOMResult signResult = new DOMResult();
            transformerFactory.newTransformer().transform(new DOMSource(document), signResult);

            return signResult;
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                MarshalException | XMLSignatureException | TransformerException e) {
            throw new Exception("Couldn't sign Application request", e);
        }
    }

    public boolean validate(Document signedRequest, String alias, boolean deep) throws Exception {
        X509Certificate certificate = (X509Certificate) (keyStore.getCertificate(alias));
        PublicKey pub = certificate.getPublicKey();

        NodeList nl = signedRequest.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        DOMValidateContext dvc = new DOMValidateContext(pub, nl.item(0));
        dvc.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);

        XMLSignature signature = xmlSignatureFactory.unmarshalXMLSignature(dvc);

        boolean coreValidity = signature.validate(dvc);

        if (!coreValidity) {
            System.err.println("Signature failed core validation");
            if (deep) {
                boolean sv = signature.getSignatureValue().validate(dvc);
                System.err.println("signature validation status: " + sv);
                // Check the validation status of each Reference.
                Iterator i = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; i.hasNext(); j++) {
                    Reference ref = (Reference) i.next();
                    boolean refValid = ref.validate(dvc);
                    System.err.println("ref[" + j + "] validity status: " + refValid);
                    if (!refValid) {
                        BufferedReader in = new BufferedReader(new InputStreamReader(ref.getDigestInputStream()));
                        String line;
                        while ((line = in.readLine()) != null) {
                            System.err.println(line);
                        }
                    }
                }
            }
        } else {
            System.err.println("Signature passed core validation");
        }

        return coreValidity;


    }


}
