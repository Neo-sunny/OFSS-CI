import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Cryptor
{
  private static SecretKey key;
  private static String transform = "DESede/ECB/PKCS5Padding";
  private static final char[] hexDigit = { 
    '0', '1', '2', '3', '4', '5', '6', '7', 
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
  private static final String hexIndex = "0123456789abcdef          ABCDEF";

  public static void seed(String sSeed)
  {
    if (sSeed != null) {
      byte[] eKey;
      try {
        SecureRandom secRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] bSeed = hexToBytes(sSeed);
        secRandom.setSeed(bSeed);

        KeyGenerator keygen = KeyGenerator.getInstance("DESede");
        keygen.init(168);
        keygen.init(secRandom);
        key = keygen.generateKey();

        eKey = key.getEncoded();
      } catch (Exception ex) {
        ex.printStackTrace();
      }
    }
  }

  public static String encrypt(String sText)
  {
    return bytesToHex(encrypt(sText.getBytes()));
  }

  public static byte[] encrypt(byte[] cText) {
    if (key == null) {
      System.err.println("[FATAL] - Cryptor not seeded; unable to proceed");
      return null;
    }

    try
    {
      if ((cText == null) || (cText.length == 0)) { return null;
      }

      Cipher cipher = Cipher.getInstance(transform);
      cipher.init(1, key);

      byte[] eText = cipher.doFinal(cText);

      return eText;
    } catch (Exception ex) {
      ex.printStackTrace();
      return null;
    }
  }

  public static String decrypt(String sText)
  {
    return new String(decrypt(hexToBytes(sText)));
  }

  public static byte[] decrypt(byte[] eText) {
    if (key == null) {
      System.err.println("[FATAL] - Cryptor not seeded; unable to proceed");
      return null;
    }

    try
    {
      if ((eText == null) || (eText.length == 0)) { return null;
      }

      Cipher cipher = Cipher.getInstance(transform);
      cipher.init(2, key);

      byte[] cText = cipher.doFinal(eText);

      return cText;
    } catch (Exception ex) {
      ex.printStackTrace();
      return null;
    }
  }

  public static String bytesToHex(byte[] data)
  {
    int top;
    try
    {
      top = 0;
      int len = data.length;
      char[] output = new char[2 * len];

      for (int i = 0; i < len; ++i) {
        output[(top++)] = hexDigit[(data[i] >> 4 & 0xF)];
        output[(top++)] = hexDigit[(data[i] & 0xF)];
      }

      return new String(output);
    } catch (Exception ex) {
      ex.printStackTrace();
      return null; }
  }

  public static String stringToHex(String data) {
    int top;
    try {
      top = 0;
      int len = data.length();
      char[] output = new char[2 * len];

      for (int i = 0; i < len; ++i) {
        output[(top++)] = hexDigit[(data.charAt(i) >> '\4' & 0xF)];
        output[(top++)] = hexDigit[(data.charAt(i) & 0xF)];
      }

      return new String(output);
    } catch (Exception ex) {
      ex.printStackTrace();
      return null;
    }
  }

  public static byte[] hexToBytes(String s)
  {
    int l;
    try
    {
      l = s.length() / 2;
      byte[] data = new byte[l];
      int j = 0;

      for (int i = 0; i < l; ++i)
      {
        char c = s.charAt(j++);
        int n = "0123456789abcdef          ABCDEF".indexOf(c);
        int b = (n & 0xF) << 4;
        c = s.charAt(j++);
        n = "0123456789abcdef          ABCDEF".indexOf(c);
        b += (n & 0xF);
        data[i] = (byte)b;
      }

      return data;
    } catch (Exception ex) {
      ex.printStackTrace();
      return null; }
  }

  public static String hexToString(String s) {
    int l;
    try {
      l = s.length() / 2;
      char[] data = new char[l];
      int j = 0;

      for (int i = 0; i < l; ++i)
      {
        char c = s.charAt(j++);
        int n = "0123456789abcdef          ABCDEF".indexOf(c);
        int b = (n & 0xF) << 4;
        c = s.charAt(j++);
        n = "0123456789abcdef          ABCDEF".indexOf(c);
        b += (n & 0xF);
        data[i] = (char)b;
      }

      return new String(data);
    } catch (Exception ex) {
      ex.printStackTrace();
      return null;
    }
  }

  public static void sop(String s)
  {
    System.out.println(s);
  }

  public static String kbInput() throws Exception
  {
    BufferedReader d;
    try {
      d = new BufferedReader(new InputStreamReader(System.in));
      String str = d.readLine();
      return str;
    } catch (Exception e) {
      sop("Got an exception in : kbInput :" + e);
      return null;
    }
  }

  public static void main(String[] args)
  {
    try
    {
      sop("Enter seed:");
      String sSeed = kbInput();
      seed(sSeed);
      boolean more = true;

      if (!(more)) {
        sop("Would you like to encrypt one more (y/n) :");
        String oneMore = kbInput();
        if (!(oneMore.trim().toUpperCase().equals("Y")))
        {
          sop("Exiting Cryptor...");
        }
      }
      else
      {
        sop("Enter password to be encrypted: ");
        String sClear = kbInput();

        if (sClear == null) {
          sop("No Password entered for encryption. Ignoring entry..");
        } else {
          sop("processing . . . \n");
         String sEncrypt = encrypt(sClear);
          sop("encrypted: '" + sEncrypt + "'");
        }
        sop("Enter password to be decrypted: ");
        String sEncrypt = kbInput();

        String sDecrypt = decrypt(sEncrypt);
        sop("check: '" + sDecrypt + "'");
        more = false;
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}