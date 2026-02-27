package com.otus.securehomework.data.source.local

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Calendar
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.security.auth.x500.X500Principal

class SecurityManager @Inject constructor(private val context: Context) {

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun encrypt(data: String?): String? {
        if (data == null) return null
        return try {
            val cipher = getCipher(Cipher.ENCRYPT_MODE)
            val iv = cipher.iv
            val encryptedData = cipher.doFinal(data.toByteArray())
            val combined = ByteArray(iv.size + encryptedData.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(encryptedData, 0, combined, iv.size, encryptedData.size)
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun decrypt(encryptedDataWithIv: String?): String? {
        if (encryptedDataWithIv == null) return null
        return try {
            val combined = Base64.decode(encryptedDataWithIv, Base64.NO_WRAP)
            val ivSize = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) 12 else 16
            if (combined.size <= ivSize) return null
            val iv = combined.copyOfRange(0, ivSize)
            val encryptedData = combined.copyOfRange(ivSize, combined.size)
            val cipher = getCipher(Cipher.DECRYPT_MODE, iv)
            String(cipher.doFinal(encryptedData))
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    private fun getCipher(mode: Int, iv: ByteArray? = null): Cipher {
        val transformation = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            AES_TRANSFORMATION_GCM
        } else {
            AES_TRANSFORMATION_CBC
        }
        val cipher = Cipher.getInstance(transformation)
        val key = getSecretKey()
        if (mode == Cipher.ENCRYPT_MODE) {
            cipher.init(mode, key)
        } else {
            val params = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                GCMParameterSpec(128, iv)
            } else {
                IvParameterSpec(iv)
            }
            cipher.init(mode, key, params)
        }
        return cipher
    }

    private fun getSecretKey(): SecretKey {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val keyEntry = keyStore.getEntry(AES_ALIAS, null) as? KeyStore.SecretKeyEntry
            keyEntry?.secretKey ?: generateAesKey()
        } else {
            getOrGenerateAesKeyLegacy()
        }
    }

    private fun generateAesKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            AES_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun getOrGenerateAesKeyLegacy(): SecretKey {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encryptedKey = prefs.getString(ENCRYPTED_AES_KEY, null)
        return if (encryptedKey != null) {
            val encryptedBytes = Base64.decode(encryptedKey, Base64.NO_WRAP)
            SecretKeySpec(decryptAesKeyWithRsa(encryptedBytes), "AES")
        } else {
            val aesKey = ByteArray(16)
            SecureRandom().nextBytes(aesKey)
            val encryptedBytes = encryptAesKeyWithRsa(aesKey)
            prefs.edit().putString(ENCRYPTED_AES_KEY, Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)).apply()
            SecretKeySpec(aesKey, "AES")
        }
    }

    private fun encryptAesKeyWithRsa(aesKey: ByteArray): ByteArray {
        val publicKey = getOrGenerateRsaKeyPair().public
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(aesKey)
    }

    private fun decryptAesKeyWithRsa(encryptedAesKey: ByteArray): ByteArray {
        val entry = keyStore.getEntry(RSA_ALIAS, null) as? KeyStore.PrivateKeyEntry
        val privateKey = entry?.privateKey ?: throw IllegalStateException("RSA private key not found")
        val cipher = Cipher.getInstance(RSA_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(encryptedAesKey)
    }

    private fun getOrGenerateRsaKeyPair(): java.security.KeyPair {
        if (!keyStore.containsAlias(RSA_ALIAS)) {
            val start = Calendar.getInstance()
            val end = Calendar.getInstance().apply { add(Calendar.YEAR, 30) }
            val spec = KeyPairGeneratorSpec.Builder(context)
                .setAlias(RSA_ALIAS)
                .setSubject(X500Principal("CN=$RSA_ALIAS"))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()
            val generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
            generator.initialize(spec)
            generator.generateKeyPair()
        }
        val entry = keyStore.getEntry(RSA_ALIAS, null) as KeyStore.PrivateKeyEntry
        return java.security.KeyPair(entry.certificate.publicKey, entry.privateKey)
    }

    companion object {
        private const val AES_ALIAS = "aes_key"
        private const val RSA_ALIAS = "rsa_key"
        private const val PREFS_NAME = "secure_prefs"
        private const val ENCRYPTED_AES_KEY = "encrypted_aes_key"
        private const val AES_TRANSFORMATION_GCM = "AES/GCM/NoPadding"
        private const val AES_TRANSFORMATION_CBC = "AES/CBC/PKCS7Padding"
        private const val RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    }
}
