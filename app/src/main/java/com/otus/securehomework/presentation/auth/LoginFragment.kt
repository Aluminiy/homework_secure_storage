package com.otus.securehomework.presentation.auth

import android.os.Bundle
import android.view.View
import androidx.biometric.BiometricManager
import androidx.core.widget.addTextChangedListener
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Observer
import androidx.lifecycle.asLiveData
import androidx.lifecycle.lifecycleScope
import com.otus.securehomework.R
import com.otus.securehomework.data.Response
import com.otus.securehomework.data.source.local.BiometricHelper
import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.databinding.FragmentLoginBinding
import com.otus.securehomework.presentation.enable
import com.otus.securehomework.presentation.handleApiError
import com.otus.securehomework.presentation.home.HomeActivity
import com.otus.securehomework.presentation.startNewActivity
import com.otus.securehomework.presentation.visible
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class LoginFragment : Fragment(R.layout.fragment_login) {

    private lateinit var binding: FragmentLoginBinding
    private val viewModel by viewModels<AuthViewModel>()

    @Inject
    lateinit var biometricHelper: BiometricHelper

    @Inject
    lateinit var userPreferences: UserPreferences

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding = FragmentLoginBinding.bind(view)

        binding.progressbar.visible(false)
        binding.buttonLogin.enable(false)

        val canAuthenticate = biometricHelper.canAuthenticate()
        if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
            binding.checkBoxBiometric.visible(true)
            lifecycleScope.launch {
                val isEnabled = userPreferences.biometricEnabled.first()
                binding.checkBoxBiometric.isChecked = isEnabled
            }
        } else {
            binding.checkBoxBiometric.visible(false)
        }

        viewModel.loginResponse.observe(viewLifecycleOwner, Observer {
            binding.progressbar.visible(it is Response.Loading)
            when (it) {
                is Response.Success -> {
                    lifecycleScope.launch {
                        viewModel.saveAccessTokens(
                            it.value.user.access_token!!,
                            it.value.user.refresh_token!!
                        )
                        if (binding.checkBoxBiometric.visibility == View.VISIBLE) {
                            userPreferences.setBiometricEnabled(binding.checkBoxBiometric.isChecked)
                        }
                        requireActivity().startNewActivity(HomeActivity::class.java)
                    }
                }
                is Response.Failure -> handleApiError(it) { login() }
                Response.Loading -> Unit
            }
        })
        binding.editTextTextPassword.addTextChangedListener {
            val email = binding.editTextTextEmailAddress.text.toString().trim()
            binding.buttonLogin.enable(email.isNotEmpty() && it.toString().isNotEmpty())
        }
        binding.buttonLogin.setOnClickListener {
            login()
        }
    }

    private fun login() {
        val email = binding.editTextTextEmailAddress.text.toString().trim()
        val password = binding.editTextTextPassword.text.toString().trim()
        viewModel.login(email, password)
    }
}