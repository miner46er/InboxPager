/*
 * Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
 *
 * This file is part of GNU Crypto.
 *
 * GNU Crypto is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * GNU Crypto is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to the
 *
 *    Free Software Foundation Inc.,
 *    59 Temple Place - Suite 330,
 *    Boston, MA 02111-1307
 *    USA
 *
 * Linking this library statically or dynamically with other modules is
 * making a combined work based on this library.  Thus, the terms and
 * conditions of the GNU General Public License cover the whole
 * combination.
 *
 * As a special exception, the copyright holders of this library give
 * you permission to link this library with independent modules to
 * produce an executable, regardless of the license terms of these
 * independent modules, and to copy and distribute the resulting
 * executable under terms of your choice, provided that you also meet,
 * for each linked independent module, the terms and conditions of the
 * license of that module.  An independent module is a module which is
 * not derived from or based on this library.  If you modify this
 * library, you may extend this exception to your version of the
 * library, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 **/

/*
 * A placeholder for <i>names</i> and <i>literals</i> used throughout this library.
 *
 * @version $Revision: 1.24 $
 **/
package gnu.crypto;

public interface Registry {

   String RIJNDAEL_CIPHER = "rijndael";
   String TWOFISH_CIPHER = "twofish";
   String SHAMAQ_CIPHER = "shamaq";
   String NULL_CIPHER = "null";

   // AES is synonymous to Rijndael for 128-bit block size only.
   String AES_CIPHER = "aes";

   // Electronic CodeBook mode.
   String ECB_MODE = "ecb";

   // Counter (NIST) mode.
   String CTR_MODE = "ctr";

   // Integer Counter Mode (David McGrew).
   String ICM_MODE = "icm";

   // Output Feedback Mode (NIST).
   String OFB_MODE = "ofb";

   // Cipher block chaining mode (NIST).
   String CBC_MODE = "cbc";

   // Cipher feedback mode (NIST).
   String CFB_MODE = "cfb";

   // PKCS#7 padding scheme.
   String PKCS7_PAD = "pkcs7";

   // Trailing Bit Complement padding scheme.
   String TBC_PAD = "tbc";
}
