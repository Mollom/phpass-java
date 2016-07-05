package com.mollom.phpass;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Generates and verifies password hashes.
 */
public class PasswordHasher {

  private static final Logger logger = Logger.getLogger("com.mollom.phpass");

  /**
   * Non-standard compliant Base64 character mapping.
   *
   * Phpass's Base64 character mapping table deviates from RFC 2045:
   * ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
   */
  private static final char[] BASE64_CHAR_MAPPING = {
    '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

  private static final int HASH_ITERATIONS = 15;

  private static final int HASH_SIZE = 55;

  private MessageDigest messageDigest;
  private SecureRandom secureRandom;

  public PasswordHasher() {
    secureRandom = new SecureRandom();
    try {
      messageDigest = MessageDigest.getInstance("SHA-512");
    } catch (NoSuchAlgorithmException e) {
      logger.log(Level.SEVERE, "Could not create a SHA-512 digest.");
    }
  }

  /**
   * @return If the password matches the hash.
   */
  public boolean isMatch(String password, String storedHash) {
    // Support updated drupal hashes here by first md5 hashing the input
    // if it begins with a U - this was done often during upgrades of 
    // Drupal 5 after md5 hashing was dropped by drupal in favor of sha-512
    if(storedHash.startsWith("U")) {
      password = md5(password);
      // We also need to lop off the U from the sha-512 stored hash
      storedHash = storedHash.substring(1,storedHash.length());
    }
    // The first 12 digits of the hash is used to modify the encryption.
    String setting = storedHash.substring(0, 12);
    return storedHash.equals(encrypt(password, setting));
  }

  /**
   * The first 3 characters of the setting is ignored; it is used to describe
   * the hashing algorithm, but we're always using SHA-512
   *
   * @return Encrypted hash of the password using the given settings
   */
  private String encrypt(String password, String setting) {
    String salt = setting.substring(4, 12);
    // The index in our mapping table of the 4th character of the setting is
    // used to determine the number of times we apply the SHA512 hashing
    int log2Iterations = new String(BASE64_CHAR_MAPPING).indexOf(setting.substring(3, 4));
    // We apply the SHA-512 hashing log2Iterations^2 times
    int iterations = (int) Math.pow(2, log2Iterations);

    // Initially hash the password with the salt
    byte[] hash = messageDigest.digest((salt + password).getBytes());
    // Running the hash lots of times causes the hash function to be slow and
    // expensive, defending against brute-force attacks
    for (int i = 0; i < iterations; i++) {
      // At each iteration, re-salt using the password
      // This reduces the risk of collisions
      hash = messageDigest.digest(concatArrays(hash, password.getBytes()));
    }

    // The final hash is the SHA'ed hash appended at the end of the setting
    String encodedHash = setting + encodeBase64(hash);
    // I have no idea why we have to truncate the hash at HASH_SIZE characters;
    // in fact that sounds incredibly wrong in every way possible, but that's
    // what PHPass does so we have to mimic the behavior
    String truncatedEncodedHash = encodedHash.substring(0, HASH_SIZE);
    return truncatedEncodedHash;
  }

  /**
   * @return A randomly salted hash for the given password.
   */
  public String createHash(String password) {
    return encrypt(password, generateSetting());
  }

  /**
   * Generates a random Base64 salt prefixed with settings for the hash.
   */
  private String generateSetting() {
    String algorithm = "$S$"; // Always use SHA512
    String iterations = Character.toString(BASE64_CHAR_MAPPING[HASH_ITERATIONS]);
    String salt = generateRandomSalt(8);

    return algorithm + iterations + salt;
  }

  /**
   * Generate a random salt using the Base64 alphabet of the given number of
   * characters
   */
  private String generateRandomSalt(int characters) {
    StringBuilder stringBuilder = new StringBuilder();

    for (int i = 0; i < characters; i++) {
      stringBuilder.append(BASE64_CHAR_MAPPING[secureRandom.nextInt(64)]);
    }

    return stringBuilder.toString();
  }

  /**
   * @return The second array appended at the end of the first array.
   */
  private byte[] concatArrays(byte[] first, byte[] second) {
    byte[] result = Arrays.copyOf(first, first.length + second.length);
    System.arraycopy(second, 0, result, first.length, second.length);
    return result;
  }

  /**
   * We have to use our own encode Base64 function here the one used by PHPass
   * does not follow RFC 2045, and hence no other libraries out there actually
   * supports it.
   *
   * If the end contains fewer than 24 input bits, do NOT pad, stop producing
   * output bits.
   *
   * @return Base64 encoding of the given digest
   */
  private String encodeBase64(byte[] input) {
    StringBuilder builder = new StringBuilder();
    int i = 0;

    // Normally, Base64 encoding looks at 24-bit chunks of the input data, but
    // because we're not doing zero-padding at the end, we must look at each
    // byte one at a time to make sure we don't get IndexOutOfBoundsExceptions
    // Base64 has 64 (2^6) characters in its dictionary, and is represented by
    // 6-bit chunks
    // It is acceptable to evaluate a 6-bit chunk even if we only have partial
    // information about it (i.e. there are 16 bits of input data, so we can
    // only get a 4 bit chunk for the final character) because the bitwise shift
    // will automatically pad zeros for evaluation
    do {
      // Build the first 8-bit chunk
      int inputGroup = unsignedByteToSignedInt(input[i++]);

      // Append the alphabet mapping for the first 6-bit chunk
      builder.append(BASE64_CHAR_MAPPING[inputGroup & 0x3f]);

      // Build the second 8-bit chunk
      if (i < input.length) {
        inputGroup += unsignedByteToSignedInt(input[i]) << 8;
      }

      // Append the alphabet mapping for the second 6-bit chunk
      // chunk with zeros to do the mapping
      builder.append(BASE64_CHAR_MAPPING[(inputGroup >> 6) & 0x3f]);

      // If we didn't push the second 8-bit chunk, stop evaluating because we're
      // out of inputs
      if (i++ >= input.length) {
        break;
      }

      // Build the third 8-bit chunk of the inputGroup
      if (i < input.length) {
        inputGroup += unsignedByteToSignedInt(input[i]) << 16;
      }

      // Append the alphabet mapping for the third 6-bit chunk
      builder.append(BASE64_CHAR_MAPPING[(inputGroup >> 12) & 0x3f]);

      // If we didn't push the third 8-bit chunk, stop evaluating because we're
      // out of inputs
      if (i++ >= input.length) {
        break;
      }

      // Append the alphabet mapping for the fourth 6-bit chunk
      builder.append(BASE64_CHAR_MAPPING[(inputGroup >> 18) & 0x3f]);
    } while (i < input.length);

    return builder.toString();
  }

  /**
   * Because Java stores bytes as signed a signed value (-128, 127), we need to
   * do a conversion to get the (0, 255) unsigned byte value that the algorithm
   * expects
   */
  private int unsignedByteToSignedInt(int value) {
    return value & 0xFF;
  }

  public static String md5( String input ) {
    try {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] array = md.digest(input.getBytes("UTF-8"));
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < array.length; i++) {
            sb.append(String.format("%02x", array[i]));
        }
        return sb.toString();
    } catch (java.security.NoSuchAlgorithmException nse) {
      return null;
    } catch (java.io.UnsupportedEncodingException uee) {
      return null;            
    }
  }
}
