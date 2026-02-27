package com.otus.securehomework.presentation.splash

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.lifecycle.asLiveData
import androidx.lifecycle.lifecycleScope
import com.otus.securehomework.R
import com.otus.securehomework.data.source.local.BiometricHelper
import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.presentation.auth.AuthActivity
import com.otus.securehomework.presentation.home.HomeActivity
import com.otus.securehomework.presentation.startNewActivity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class SplashActivity : AppCompatActivity() {

    @Inject
    lateinit var userPreferences: UserPreferences

    @Inject
    lateinit var biometricHelper: BiometricHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)

        lifecycleScope.launch {
            val token = userPreferences.accessToken.first()
            if (token == null) {
                startNewActivity(AuthActivity::class.java)
            } else {
                val biometricEnabled = userPreferences.biometricEnabled.first()
                val canAuthenticate = biometricHelper.canAuthenticate()

                if (biometricEnabled && canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                    showBiometricPrompt()
                } else {
                    startNewActivity(HomeActivity::class.java)
                }
            }
        }
    }

    private fun showBiometricPrompt() {
        biometricHelper.showBiometricPrompt(
            activity = this,
            title = "Biometric Login",
            subtitle = "Log in using your biometric credential",
            description = "Confirm your identity to continue",
            onSuccess = {
                startNewActivity(HomeActivity::class.java)
            },
            onError = { _, errString ->
                Toast.makeText(this, "Authentication error: $errString", Toast.LENGTH_SHORT).show()
                // Depending on requirements, you might want to fall back to password or close app
            },
            onFailed = {
                Toast.makeText(this, "Authentication failed", Toast.LENGTH_SHORT).show()
            }
        )
    }
}