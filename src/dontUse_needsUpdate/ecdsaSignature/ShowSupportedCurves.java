package dontUse_needsUpdate.ecdsaSignature;

import java.security.Security;


//Helper Class to print all supported Epileptic Curves for use in EC
//Refer to http://safecurves.cr.yp.to for a list of save epileptic curves

//keine der Supporteten Kurven ist laut savecurves safe
public class ShowSupportedCurves
{
    public static void main(String[] args) {
            String[] curves = Security.getProvider("SunEC").getProperty("AlgorithmParameters.EC SupportedCurves").split("\\|");
        for(String curve: curves)
            System.out.println(curve);
        }
}
