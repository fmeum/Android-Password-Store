/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.onboarding.fragments

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.core.view.ViewCompat
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.databinding.FragmentKeySelectionBinding
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.OpenKeychainCancelledException
import app.passwordstore.util.crypto.OpenKeychainClient
import app.passwordstore.util.extensions.commitChange
import app.passwordstore.util.extensions.finish
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.windowInsetsLambda
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.onOk
import com.google.android.material.snackbar.Snackbar
import dagger.hilt.android.AndroidEntryPoint
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.launch
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class KeySelectionFragment : Fragment(R.layout.fragment_key_selection) {

  @Inject @SettingsPreferences lateinit var settings: SharedPreferences
  @Inject lateinit var dispatcherProvider: DispatcherProvider
  private val binding by viewBinding(FragmentKeySelectionBinding::bind)
  private val openKeychain =
    OpenKeychainClient({ requireContext() }, { dispatcherProvider }, this, this)
  private val gpgKeySelectAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == AppCompatActivity.RESULT_OK) {
        val data = result.data ?: return@registerForActivityResult
        val selectedKeyId =
          data.getStringExtra(PGPKeyListActivity.EXTRA_SELECTED_KEY)
            ?: return@registerForActivityResult
        lifecycleScope.launch { initialiseStore(selectedKeyId, useOpenKeychain = false) }
      } else {
        requireActivity()
          .snackbar(
            message = getString(R.string.gpg_key_select_mandatory),
            length = Snackbar.LENGTH_LONG,
          )
      }
    }

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    super.onViewCreated(view, savedInstanceState)
    ViewCompat.setOnApplyWindowInsetsListener(view, windowInsetsLambda)

    binding.selectKey.setOnClickListener {
      gpgKeySelectAction.launch(PGPKeyListActivity.newIntent(requireContext(), keySelection = true))
    }
    // Offer OpenKeychain (e.g. for YubiKey users) only if it is installed
    binding.selectKeyOpenkeychain.isVisible = OpenKeychainClient.isInstalled(requireContext())
    binding.selectKeyOpenkeychain.setOnClickListener { selectKeysInOpenKeychain() }
  }

  private fun selectKeysInOpenKeychain() {
    lifecycleScope.launch {
      openKeychain
        .selectKeyIds()
        .onOk { keyIds ->
          if (keyIds.isEmpty()) {
            requireActivity()
              .snackbar(
                message = getString(R.string.openkeychain_no_keys_selected),
                length = Snackbar.LENGTH_LONG,
              )
          } else {
            val identifiers = keyIds.joinToString("\n") { PGPIdentifier.KeyId(it).toString() }
            initialiseStore(identifiers, useOpenKeychain = true)
          }
        }
        .onErr { e ->
          logcat { e.asLog() }
          if (e !is OpenKeychainCancelledException) {
            requireActivity()
              .snackbar(
                message = getString(R.string.openkeychain_error, e.message ?: ""),
                length = Snackbar.LENGTH_LONG,
              )
          }
        }
    }
  }

  /**
   * Writes [identifiers] to the store's root `.gpg-id`, marks the repository as initialised and, if
   * the keys were picked in OpenKeychain, switches the PGP backend to OpenKeychain as well.
   */
  private suspend fun initialiseStore(identifiers: String, useOpenKeychain: Boolean) {
    val gpgIdentifierFile = File(PasswordRepository.getRepositoryDirectory(), ".gpg-id")
    gpgIdentifierFile.writeText(identifiers.trimEnd() + "\n")
    settings.edit {
      putBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, true)
      if (useOpenKeychain) putBoolean(PreferenceKeys.USE_OPENKEYCHAIN, true)
    }
    requireActivity()
      .commitChange(getString(R.string.git_commit_gpg_id, getString(R.string.app_name)))
    finish()
  }

  companion object {

    fun newInstance() = KeySelectionFragment()
  }
}
