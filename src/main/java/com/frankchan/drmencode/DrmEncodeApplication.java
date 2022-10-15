package com.frankchan.drmencode;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.CollectionUtils;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Stream;

@SpringBootApplication
public class DrmEncodeApplication {
    /**
     * cipher 格式
     */
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    /**
     * AES
     */
    private static final String AES = "AES";

    /**
     * SHA-256
     */
    private static final String SHA_256 = "SHA-256";

    /**
     * GCM_TAG_LENGTH
     */
    private static final int GCM_TAG_LENGTH = 16;

    public static void main(String[] args) {
        final String text = "yJ3pPh4RItrcgckEtqjS+Q==";
        final String content = "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";
        final String indiv3Key = "41FCD0AB935789C59193A29D7E184B8E";

        //        final String text = "yJ3rbktFd46Mh55XtqGM8Q==";
        //        final String content = "ExNAOahxxpEO6utdfqV6xjhfrjn+giAo5TlQICZcE05UNBWOoBo+s8YQrOhFuRpM8aCqKkNd+f8+AOS+xXPLwpFsRmd1wgWv8C1Qstqv9GlDDZKPoxDzuyQswroHEDxX+lvxM1BHXECn1Jy8f6YIlfz7v+YXoi2PT1LumN74Kaj8Ho7b28wiWqJBgdw/19+ZwFrH0N4+2aIGurIoPhkepxripSHaoN/vXepklVWNgbJLvhDwQiRgt0WV32wyx/ESIzs3ZRZzO7zhGYFm9geOXpZyov330/qvKH6iXMmq6fJFQFo2vQjyAnuVYyGTvzD2ME0CMy9TcRtzJpxVgvz7guw6eGYH6lkSSlczMLvxoymnzDyZCmcc2UChajE+2X0wlEz2/Gi2zzA4S0k17gPbTALI3khlp3Moo+obaJy5/ODdy1xBHdSXeylqum2Uug8NOtdv018LIXkCvnh7ao88x+1TJt0Pwnq46qOYUWGG8KEsUAWPqXIgU8a/oeRLNtmM27VHho9jty91hQcunh9orKaJYhUllCcRnrrMetHeqHKdDaSw70yVUcCtbgKBEkGYu7zIT5IshSTyRKO9YjVS3+qOUQQrB3ThDcqPKlMBeghHpOId4LrNIBV7+uejWajPu7P6EllR9OEWnEpabnTKE6u5iASkTz+Mb+2uHSqCwUcmx5tBeAmA2TRd48fvmrBHThv9xQ3/AURUEhnR0/X9GIumdzJofhWJ/2DMuMTj9Evg6/v/yM8SA9v5NPbYsxElqqvajImNO6sf/+Prrf9eFcuXXLqihRjHND5U4I1aIYT3+L633dJ4L79TA1O8nJv1xMh7umkiVvDAWCJh7llB3igEfEZDKi/WobG0iJK4nI/vOS1xttgywXX+SA3IKvfOuwBLgeUeRTN5bKlMa+jSGct1Y0D4P159xtkT8DW7y2m7wKiEy1xSu5Klr6JsTuQusUhy0Mc43LAHuXgF1o676RhEkLzaOgtfuvEz5zNU4EKEJrpkKon8F69FjgMGWmI4Sg/3DgFrDrV9PXUAfynouOH6UhhmhQgvfpGXSfzfVvanbT75DdmBV4ya2Q6KzUJhiLnt5DcKwrVF0xtCc88OTKAbi7yYaFzv/9XdNbXg0fKNihJx6S19qFsm2+n4nkE1/WlOVXU4UqV+T+AWTyccqYF43u53b1RqAg/pSb0hb1BcZ3nXvsMveDLTFxnroemrlwf8qcyEs8p68DHqszkLL+o3KyRU5ZFvTtso1v0Br5SDlMkmiiZTSKnBLAaQnS8YLYTS9WrwzgrYI5RK5txK4s+zIP/Z1M7aoqk1bKjzQ7NS25i0Ran3Pe3DYJUw1UGpMkStx6tB++2CNXZNEuJXx2ay0vlwP3ax7PNL74JRndK+FoVpz5jhaOVkdJWO3lOfVNccGzbRZhlk08xxnSrb6BeQZTGQeyJmMFeKQck7vz/vuQ/FS4b4FnOX5TPZwWuqxswecOMpzPeTOJ27s07WhVGwlgavQDdmuaSs3GxdyvnOxe0jq6ZCKkQ1wXQFZQRgIPNAo6k86atnrUUVIyl9xR5x8tJdyUi2ONzGR6sHN1bE7f0vErp4Tme/Mbz8TDW937uROBaF0DQ3x2I/h23JriCr/HbTEvOeleMH3kcfhhrPLko5JVhHobkzyJeWJXTvwZH5ZUPgHWb7kjhhF/Kt1vWcYzqIGOmd0DF3AfH4BM0QC7J21o97w0df2+ttopCGoIw6UZ+scC4lhZzf4h181HjRErmDUbpcDmA6OVl/Cu/fA29urmdrY9h6HT8vUbwvaRpbDO7eD00pINzncdBIV5GXPAPBCyZ0OFOZlXT87VrWx8FhbC1TVnyrFihjBdEMDYYaCRNs2ToFfZdjZesYaefip0HwfdUuiMkv/BqG3F0p5fDmajsGTugxG0RWcrDmkVgWEQsJmgScCVh1IZR5yswHvlI6IbYjlYBhhlyFFtquW8c+NjGLtVqGfKSml72ej+Jdp6k0m6x2TvfFpNfOPewvNSuunmdUS6Lpl71aCBEN6/DiqPP5Ev4RNSPSo8CxklhT17SWUKOChOexV1g+X0jwrBaFS4Mb0zzRrWpOsJycpFEsMzfoYVx3r68mBbYnsOdTH9+fIEoBzyr0vYA3qSJO1GyIoKvqkdfn/HzPxpHr2m9I6zDtN5vhDmDsqP6ME2gCDIm/+XMqoQ9wAFMVBjeOF9VJ2mb5rr/jpDwEP8vbsyxdEE83l9ayZhVwOkegGqsuV1lShG2CFX7tsEzQvDVw6440DPj1/RF5RrLPjod6dXK6x+VnjUx4ic16X7Ths0eJMnppwNmr7ZzkDLd9H20koTsIFfobnbnZBoV/ad6ok4wHRJFAjdyM7v3OD8qqHPUloUoOT+uu7hGznPr4XM85VJA0gHaiC5rhpfJsI1m43b9/oSNqDW+CbW2rvUk8q45eYe0DdkKjk+PMnDF9+4bM8gfLhUtZ/FLCA+taFPUXw2N+mRaSV40ESMdUepWcDb8ElH3ipDOIZ/tes/YPNw730sSMzBDel69zShwLqDtaeuGmTZEAWlqoKxa9K1dP/4ONSPAZ+r8advuKegwtoUoGS3kHPYbgeWbUxQa08SPfJmkLPk7frDeGK2Lp4AG6SQ6ylsV+fDjD1YT/8vuGJFhsUO3hSfZ7eAU7bmgapRaoy4Uas/jaGZeULW/lK5jEEWn8MqP1OXv+6vltOMqEswedQg2CIAoFyqbyxQe+WVHw1DJxaFlBLyXvev1SmcRXhDLlnoeuSFodaJ1ESaaRQgyEj5TgZ3h+nZWv4SdNtQPKynQyuj4Y91IIiCrF2Z2Wkb2JuM1XAwMvPbZsVbkzoYIGQUoVrYp0FQqWP3HvQ9cprn9z2PvTTFqQyyXY78dmN6sipr/7QQ6BgNC8JHJzqEYdboOpcM22eRzrvpOFqSKbFibtCcO6DqutCl2OJCDKzBWdszOJvvfnsdHb23WMM/C4dM+DVSk0Y7cNVp+eShqQ8NLwzrBoBvFbePu6Qlonofj2Vss2vWIBD1Mf5bns/0mdIy5gOSOVm2k7pBycItw+urxO6KzJPN2VZOWmh+HuqhTcvzWmX7TsBxABnOJXlj6jbL9/1NJ0/WDMcrVtd0RvWUdV6lO/+SV7w39klwcuhs56NU9jFkoQy0IeoKzBD74YlZUxKoW0ki+19dT4M4OBqqBZ1PNWtFLQTH4MdtSfVtlL82skajjWBN4vaI5QtLyUzq21uwTjCEe4KDCs4y4K+9F6AL8LuajFnyIAEuPk3/ZMPBMdsSMPkT0xN8loj2fXDjvE4KY61K4U6q4hEo+OAKescyt7960MIOAti1RHR3NgXClrHWUuX+Wk4wBVEnPyrKngwsMM3CFjKjq3YvdCeReOIAbxC69iL8XnOCTtMDTAg2973IqAyeeWMGVhfBHI9SJAhWitFHN1r0pdT1Xi9MLxqdVsAhwt6XxDl9GaKs2duORHsCaq3ILtv9BitlVkt30bR9UWpPvMvBmA0h3guaDWpq9pdnwaqMlcuP79VgoxAcqYsHqye0DOBK3QaKhgTzewQVqHhhF6oggRzw/882Kzkqk/peTl2S5WvYR0h3Tk62jnAxTyV1D4uOGhz97v3tfllE/OynuF0Owq+mfDfhMfCljxiTlWBPT4q7O7gFZ1yNojv+WzTukW2pC4/zXQXeEnFu32jAQ6lUv1fJCQiChTa1MxOQGDQEFClnCuA6rIKNZGBtNoQyyuCO9rJq+k1cRvQU5A38vCZKOEO+iGmeYLq8eCae8T5ldbUl7yrjXNGu0vT1oyVUX52MgSDv3srUtpAmTadWO88RTitrLFBdFE94tiDcJupBjSZ44+5rCml4nuLmeeVgPSsr3Lgkp6c1i4DVVu++tmavS8k8qwanemkezo3fkhHbZFdg3McFvGvnBxhVVQQSJ+6434PtD9ZrCn4huA27dZub9+nQI=";
        //        final String indiv3Key = "3EC6836790391320EC6FBA8418F55A67";

        // step 3 對V3.cli的<KID>做base64解碼
        // step 4 對step 3的結果做rc4解密，key是Tiasfy!!
        // step 10 對step 4的結果做sha1計算
        byte[] rc4DecodeSha1 = null;
        try {
            // step 3 對V3.cli的<KID>做base64解碼
            final byte[] textDecode = decryptBase64(text);
            System.out.println("textDecode end");

            // step 4 對step 3的結果做rc4解密，key是Tiasfy!!
            final byte[] rc4Decode = decryptRc4(textDecode, "Tiasfy!!".getBytes(StandardCharsets.UTF_8));
            System.out.println("rc4Decode end");

            // step 10 對step 4的結果做sha1計算
            rc4DecodeSha1 = tohash256Deal(rc4Decode);
            System.out.println("rc4DecodeSha1 end");
        } catch (Exception e) {
            System.out.println(e);
        }

        // step 9 對V3.cli的<CONTENT>做base64解碼，長度0x710
        // step 12 對indiv3.key的前16字節做sha1計算
        // step 13 對step 9的結果做rc4解密，key是step 12的結果第12位開始16字節
        // step 14 對step 13的結果做aes解密，key是step 10的結果第8位開始16字節
        try {
            // step 9 對V3.cli的<CONTENT>做base64解碼，長度0x710
            final byte[] contentDecode = decryptBase64(content);
            System.out.println("contentDecode end");

            // step 12 對indiv3.key的前16字節做sha1計算
            final byte[] indiv3KeySha1 = tohash256Deal(indiv3Key.substring(0, 16));
            System.out.println("indiv3KeySha1 end");

            // step 13 對step 9的結果做rc4解密，key是step 12的結果第12位開始16字節
            final byte[] contentRc4Key = Arrays.copyOfRange(indiv3KeySha1, 11, 11 + 16);
            byte[] contentRc4Decode = rc4Base(contentDecode, contentRc4Key);
            System.out.println("contentRc4Decode end");

            // step 14 對step 13的結果做aes解密，key是step 10的結果第8位開始16字節
            final byte[] aesKey = Arrays.copyOfRange(rc4DecodeSha1, 7, 7 + 16);
            final String aesDecode = decryptAes256(aesKey, contentRc4Decode);
            System.out.println("aesDecode end");
        } catch (Exception e) {
            System.out.println(e);
        }

        // step 16 對step 14的<k>做base64解密

        SpringApplication.run(DrmEncodeApplication.class, args);
    }

    private static byte[] tohash256Deal(String paxx) throws Exception {
        byte[] paxxByte = paxx.getBytes(StandardCharsets.UTF_8);
        return tohash256Deal(paxxByte);
    }

    private static byte[] tohash256Deal(byte[] paxx) throws Exception {
        MessageDigest digester = MessageDigest.getInstance(SHA_256);
        digester.update(paxx);
        byte[] hex = digester.digest();
        return hex;
    }

    public static String decryptAes256(byte[] key, byte[] msg) throws Exception {

        SecretKeySpec secretKey = new SecretKeySpec(key, AES);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, key);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        //        byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(msg));
        byte[] decryptedText = cipher.doFinal(msg);
        String strDecryptedText = new String(decryptedText);

        return strDecryptedText;
    }

    public static byte[] decryptRc4(byte[] content, byte[] key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "RC4");
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] rc4Decode = cipher.doFinal(content);
        System.out.println(new String(rc4Decode, StandardCharsets.UTF_8));
        return rc4Decode;
    }

    public static byte[] decryptBase64(String content) throws Exception {
        final Base64.Decoder contentDecoder = Base64.getDecoder();
        byte[] contentByte = content.getBytes(StandardCharsets.UTF_8);
        byte[] contentDecode = contentDecoder.decode(contentByte);
        System.out.println(new String(contentDecode, StandardCharsets.UTF_8));
        return contentDecode;
    }

    private static byte[] initKey(byte[] aKey) {
        byte[] state = new byte[256];
        for (int i = 0; i < 256; i++) {
            state[i] = (byte) i;
        }
        int index1 = 0;
        int index2 = 0;
        if (aKey.length == 0)
            return null;
        for (int i = 0; i < 256; i++) {
            index2 = ((aKey[index1] & 0xff) + (state[i] & 0xff) + index2) & 0xff;
            byte tmp = state[i];
            state[i] = state[index2];
            state[index2] = tmp;
            index1 = (index1 + 1) % aKey.length;
        }
        return state;
    }

    private static byte[] rc4Base(byte[] input, byte[] aKey) {
        int x = 0;
        int y = 0;
        byte[] key = initKey(aKey);
        int xorIndex;
        byte[] result = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            x = (x + 1) & 0xff;
            y = ((key[x] & 0xff) + y) & 0xff;
            byte tmp = key[x];
            key[x] = key[y];
            key[y] = tmp;
            xorIndex = ((key[x] & 0xff) + (key[y] & 0xff)) & 0xff;
            result[i] = (byte) (input[i] ^ key[xorIndex]);
        }
        return result;
    }
}
