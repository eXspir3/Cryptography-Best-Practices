package ecdsaSignature;

import java.security.Security;
import java.util.Arrays;


//Helper Class to print all supported Epileptic Curves for use in ECDSA
//Refer to http://safecurves.cr.yp.to for a list of save epileptic curves

public class ShowSupportedCurves
{
    public static void main(String[] args)
        throws Exception{
            String[] curves = Security.getProvider("SunEC").getProperty("AlgorithmParameters.EC SupportedCurves").split("\\|");
        System.out.println(Arrays.toString(curves));
        }
}
