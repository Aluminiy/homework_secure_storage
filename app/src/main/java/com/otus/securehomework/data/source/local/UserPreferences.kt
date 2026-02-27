package com.otus.securehomework.data.source.local

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

private const val dataStoreFile: String = "securePref"

class UserPreferences
@Inject constructor(
    private val context: Context,
    private val securityManager: SecurityManager
) {

    val accessToken: Flow<String?>
        get() = context.dataStore.data.map { preferences ->
            securityManager.decrypt(preferences[ACCESS_TOKEN])
        }

    val refreshToken: Flow<String?>
        get() = context.dataStore.data.map { preferences ->
            securityManager.decrypt(preferences[REFRESH_TOKEN])
        }

    val biometricEnabled: Flow<Boolean>
        get() = context.dataStore.data.map { preferences ->
            preferences[BIOMETRIC_ENABLED] ?: false
        }

    suspend fun saveAccessTokens(accessToken: String?, refreshToken: String?) {
        context.dataStore.edit { preferences ->
            accessToken?.let { preferences[ACCESS_TOKEN] = securityManager.encrypt(it)!! }
            refreshToken?.let { preferences[REFRESH_TOKEN] = securityManager.encrypt(it)!! }
        }
    }

    suspend fun setBiometricEnabled(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[BIOMETRIC_ENABLED] = enabled
        }
    }

    suspend fun clear() {
        context.dataStore.edit { preferences ->
            preferences.clear()
        }
    }

    companion object {
        private val Context.dataStore by preferencesDataStore(name = dataStoreFile)
        private val ACCESS_TOKEN = stringPreferencesKey("key_access_token")
        private val REFRESH_TOKEN = stringPreferencesKey("key_refresh_token")
        private val BIOMETRIC_ENABLED = booleanPreferencesKey("key_biometric_enabled")
    }
}