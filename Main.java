
public class Main {

    HttpGet httpGet = null;
    DefaultHttpClient httpClient = new DefaultHttpClient;
    try {
        // client ----------- acquire outbound credential handle
        CredHandle phClientCredential = new CredHandle();
        TimeStamp ptsClientExpiry = new TimeStamp();
        assertEquals(W32Errors.SEC_E_OK, Secur32.INSTANCE.AcquireCredentialsHandle(
                null, "Negotiate", new NativeLong(Sspi.SECPKG_CRED_OUTBOUND), null, null,
                null, null, phClientCredential, ptsClientExpiry));
        // client ----------- security context
        CtxtHandle phClientContext = new CtxtHandle();
        NativeLongByReference pfClientContextAttr = new NativeLongByReference();
        // server ----------- acquire inbound credential handle
        CredHandle phServerCredential = new CredHandle();
        TimeStamp ptsServerExpiry = new TimeStamp();
        if (W32Errors.SEC_E_OK != Secur32.INSTANCE.AcquireCredentialsHandle(
                null, "Negotiate", new NativeLong(Sspi.SECPKG_CRED_INBOUND), null, null,
                null, null, phServerCredential, ptsServerExpiry))) {
            throw RuntimeException("AcquireCredentialsHandle");
        }
        // server ----------- security context
        SecBufferDesc pbServerToken = new SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);
        while(true) {
            // client ----------- initialize security context, produce a client token
            // client token returned is always new
            SecBufferDesc pbClientToken = new SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);
            // server token is empty the first time
            int clientRc = Secur32.INSTANCE.InitializeSecurityContext(
                    phClientCredential,
                    phClientContext.isNull() ? null : phClientContext,
                    "TARGET_SERVER",
                    new NativeLong(Sspi.ISC_REQ_CONNECTION),
                    new NativeLong(0),
                    new NativeLong(Sspi.SECURITY_NATIVE_DREP),
                    pbServerToken,
                    new NativeLong(0),
                    phClientContext,
                    pbClientToken,
                    pfClientContextAttr,
                    null);
            if (clientRc == W32Errors.SEC_E_OK) {
                httpGet = new HttpGet("TARGET_URL");
                httpGet.addHeader("Authorization","Negotiate" + " " + BaseEncoding.base64().encode(pbClientToken.getBytes()));
                ClosableHttpRespose httpRespose = httpClient.execute(httpGet);
                System.out.println(httpRespose.getStatusLine());
                break;
            }
            if(clientRc != W32Errors.SEC_I_CONTINUE_NEEDED) {
                throw RuntimeException("InitializeSecurityContext");
            }

            String encodedToken = BaseEncoding.base64().encode(pbClientToken.getBytes());
            httpGet = new HttpGet("TARGET_URL");
            httpGet.addHeader("Authorization","Negotiate" + " " + BaseEncoding.base64().encode(pbClientToken.getBytes()));

            ClosableHttpResponse httpResponse = httpClient.execute(httpGet);
            EntityUtils.consume(httpResponse.getEntity());

            final String continueToken = httpResponse.getFirstHeader("WWW-Authenticate").getValue().substring();
            final byte[] continueTokenBytes = BaseEncoding.base64().decode(continueToken);
            pbServerToken = new SecBufferDesc(SECBUFFER_TOKEN, continueTokenBytes);

        }

    }catch (ClientProtocolException){

     //do something
    }catch (IOException){
     //do something

    }finally{

        //release client context
        
}
