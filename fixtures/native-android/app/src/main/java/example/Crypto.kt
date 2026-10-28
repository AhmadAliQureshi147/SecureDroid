package example

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
    return cipher.doFinal(data)
}

fun hashPassword(password: String): String {
    val digest = MessageDigest.getInstance("MD5")
    return digest.digest(password.toByteArray()).joinToString("")
}

fun staticIv(): IvParameterSpec {
    return IvParameterSpec(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
}
