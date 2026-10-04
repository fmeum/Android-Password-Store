/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.crypto

import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultCaller
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts.StartIntentSenderForResult
import androidx.core.content.IntentCompat
import androidx.core.net.toUri
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.asLog
import app.passwordstore.util.extensions.getPackageInfoCompat
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.getOr
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.map
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.io.ByteArrayOutputStream
import java.io.InputStream
import kotlin.coroutines.resume
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.logcat
import me.msfjarvis.openpgpktx.util.OpenPgpApi
import me.msfjarvis.openpgpktx.util.OpenPgpServiceConnection
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpError

/** Errors that can occur while delegating a PGP operation to OpenKeychain. */
sealed class OpenKeychainException(message: String? = null, cause: Throwable? = null) :
  Exception(message, cause)

/** OpenKeychain is not installed on this device. */
data object OpenKeychainNotInstalledException :
  OpenKeychainException("OpenKeychain is not installed")

/** Binding to OpenKeychain's OpenPGP service failed. */
class OpenKeychainBindException(cause: Throwable) :
  OpenKeychainException("Could not connect to OpenKeychain", cause)

/** The user backed out of a prompt shown by OpenKeychain (PIN entry, token tap, key selection). */
data object OpenKeychainCancelledException :
  OpenKeychainException("Operation cancelled in OpenKeychain")

/** OpenKeychain reported an error through its API. */
class OpenKeychainApiException(val errorId: Int, message: String?) :
  OpenKeychainException(message ?: "OpenKeychain reported error $errorId")

/**
 * Client for the OpenPGP API exposed by OpenKeychain.
 *
 * OpenKeychain performs the actual cryptography, which is what allows hardware tokens such as
 * YubiKeys to be used: whenever OpenKeychain needs the user (to enter a PIN, to tap a token over
 * NFC, to pick a key), it hands back a [PendingIntent] that this class launches and whose result is
 * fed back into the API call. Callers only see the final outcome of an operation.
 *
 * The underlying service connection is established lazily on first use and torn down when the
 * [LifecycleOwner] passed to the constructor is destroyed.
 */
class OpenKeychainClient(
  private val contextProvider: () -> Context,
  private val dispatchers: () -> DispatcherProvider,
  caller: ActivityResultCaller,
  lifecycleOwner: LifecycleOwner,
) : DefaultLifecycleObserver {

  constructor(
    activity: ComponentActivity,
    dispatchers: () -> DispatcherProvider,
  ) : this({ activity }, dispatchers, activity, activity)

  private var serviceConnection: OpenPgpServiceConnection? = null
  private var api: OpenPgpApi? = null
  private var userInteraction: CompletableDeferred<Intent?>? = null

  private val userInteractionLauncher =
    caller.registerForActivityResult(StartIntentSenderForResult()) { result ->
      val deferred = userInteraction
      userInteraction = null
      deferred?.complete(
        if (result.resultCode == Activity.RESULT_OK) result.data else null // null = cancelled
      )
    }

  init {
    lifecycleOwner.lifecycle.addObserver(this)
  }

  override fun onDestroy(owner: LifecycleOwner) {
    userInteraction?.complete(null)
    userInteraction = null
    runCatching { serviceConnection?.unbindFromService() }
      .onErr { e -> logcat(ERROR) { e.asLog("Failed to unbind from OpenKeychain") } }
    serviceConnection = null
    api = null
  }

  /** Decrypts the stream provided by [input] into [output]. */
  suspend fun decrypt(
    input: () -> InputStream,
    output: ByteArrayOutputStream,
  ): Result<ByteArrayOutputStream, OpenKeychainException> {
    return execute(Intent(OpenPgpApi.ACTION_DECRYPT_VERIFY), input, output).map { output }
  }

  /**
   * Encrypts the stream provided by [input] into [output] for all keys matching [identifiers]. User
   * IDs are resolved to key IDs by OpenKeychain first, which lets the user disambiguate in case
   * multiple keys match.
   */
  suspend fun encrypt(
    identifiers: List<PGPIdentifier>,
    asciiArmor: Boolean,
    input: () -> InputStream,
    output: ByteArrayOutputStream,
  ): Result<ByteArrayOutputStream, OpenKeychainException> {
    val keyIds = identifiers.filterIsInstance<PGPIdentifier.KeyId>().map { it.id }.toMutableSet()
    val userIds = identifiers.filterIsInstance<PGPIdentifier.UserId>().map { it.email }
    if (userIds.isNotEmpty()) {
      val request =
        Intent(OpenPgpApi.ACTION_GET_KEY_IDS)
          .putExtra(OpenPgpApi.EXTRA_USER_IDS, userIds.toTypedArray())
      val resolved =
        execute(request).getOrElse {
          return Err(it)
        }
      keyIds += resolved.getLongArrayExtra(OpenPgpApi.RESULT_KEY_IDS)?.toList().orEmpty()
    }
    if (keyIds.isEmpty()) {
      return Err(
        OpenKeychainApiException(OpenPgpError.NO_USER_IDS, "No matching PGP keys in OpenKeychain")
      )
    }
    val request =
      Intent(OpenPgpApi.ACTION_ENCRYPT)
        .putExtra(OpenPgpApi.EXTRA_KEY_IDS, keyIds.toLongArray())
        .putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, asciiArmor)
    return execute(request, input, output).map { output }
  }

  /**
   * Lets the user pick one or more keys in OpenKeychain and returns their long key IDs. The list is
   * empty if OpenKeychain returned without a selection.
   */
  suspend fun selectKeyIds(): Result<List<Long>, OpenKeychainException> {
    return execute(Intent(OpenPgpApi.ACTION_GET_KEY_IDS)).map { result ->
      result.getLongArrayExtra(OpenPgpApi.RESULT_KEY_IDS)?.toList().orEmpty()
    }
  }

  /**
   * Runs [request] against OpenKeychain and returns its final result [Intent]. [input] is invoked
   * once per attempt because each attempt consumes the stream, and [output] is reset before every
   * attempt. Requests for user interaction are handled transparently.
   */
  private suspend fun execute(
    request: Intent,
    input: (() -> InputStream)? = null,
    output: ByteArrayOutputStream? = null,
  ): Result<Intent, OpenKeychainException> {
    val api =
      getApi().getOrElse {
        return Err(it)
      }
    var data = request
    while (true) {
      output?.reset()
      val result = withContext(dispatchers().io()) { api.executeApi(data, input?.invoke(), output) }
      when (result.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)) {
        OpenPgpApi.RESULT_CODE_SUCCESS -> return Ok(result)
        OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED -> {
          val pendingIntent =
            IntentCompat.getParcelableExtra(
              result,
              OpenPgpApi.RESULT_INTENT,
              PendingIntent::class.java,
            )
              ?: return Err(
                OpenKeychainApiException(
                  OpenPgpError.CLIENT_SIDE_ERROR,
                  "OpenKeychain requested user interaction without providing an intent",
                )
              )
          // OpenKeychain hands back the original request enriched with the user's input; the
          // action is not preserved though, so restore it before trying again.
          data =
            awaitUserInteraction(pendingIntent)?.apply { action = request.action }
              ?: return Err(OpenKeychainCancelledException)
        }
        else -> {
          val error =
            IntentCompat.getParcelableExtra(
              result,
              OpenPgpApi.RESULT_ERROR,
              OpenPgpError::class.java,
            )
          logcat(ERROR) { "OpenKeychain error ${error?.errorId}: ${error?.message}" }
          return Err(
            OpenKeychainApiException(error?.errorId ?: OpenPgpError.GENERIC_ERROR, error?.message)
          )
        }
      }
    }
  }

  private suspend fun awaitUserInteraction(pendingIntent: PendingIntent): Intent? {
    val deferred = CompletableDeferred<Intent?>()
    userInteraction?.complete(null)
    userInteraction = deferred
    withContext(dispatchers().main()) {
      userInteractionLauncher.launch(
        IntentSenderRequest.Builder(pendingIntent.intentSender).build()
      )
    }
    return deferred.await()
  }

  private suspend fun getApi(): Result<OpenPgpApi, OpenKeychainException> {
    api?.let {
      return Ok(it)
    }
    val context = contextProvider()
    if (!isInstalled(context)) return Err(OpenKeychainNotInstalledException)
    return withContext(dispatchers().main()) {
      suspendCancellableCoroutine { continuation ->
        val connection =
          OpenPgpServiceConnection(
            context,
            PROVIDER_PACKAGE,
            object : OpenPgpServiceConnection.OnBound {
              override fun onBound(service: IOpenPgpService2) {
                val boundApi = OpenPgpApi(context.applicationContext, service, dispatchers().io())
                api = boundApi
                if (continuation.isActive) continuation.resume(Ok(boundApi))
              }

              override fun onError(e: Exception) {
                logcat(ERROR) { e.asLog("Failed to bind to OpenKeychain") }
                if (continuation.isActive) continuation.resume(Err(OpenKeychainBindException(e)))
              }
            },
          )
        serviceConnection = connection
        connection.bindToService()
      }
    }
  }

  companion object {

    /** Package name of OpenKeychain, the only OpenPGP provider we bind to. */
    const val PROVIDER_PACKAGE = "org.sufficientlysecure.keychain"

    /** Returns `true` if OpenKeychain is installed on the device. */
    fun isInstalled(context: Context): Boolean {
      return runCatching {
          context.packageManager.getPackageInfoCompat(PROVIDER_PACKAGE, 0)
          true
        }
        .getOr(false)
    }

    /**
     * Shows a dialog explaining that OpenKeychain is required and offering to open its Google Play
     * or F-Droid page. [onDismiss] runs after the dialog goes away for any reason.
     */
    fun showInstallDialog(context: Context, onDismiss: () -> Unit = {}) {
      MaterialAlertDialogBuilder(context)
        .setTitle(R.string.openkeychain_not_installed_title)
        .setMessage(R.string.openkeychain_not_installed_message)
        .setPositiveButton(R.string.openkeychain_not_installed_google_play) { _, _ ->
          openUrl(context, context.getString(R.string.play_deeplink_template, PROVIDER_PACKAGE))
        }
        .setNeutralButton(R.string.openkeychain_not_installed_fdroid) { _, _ ->
          openUrl(context, context.getString(R.string.fdroid_deeplink_template, PROVIDER_PACKAGE))
        }
        .setNegativeButton(R.string.dialog_cancel, null)
        .setOnDismissListener { onDismiss() }
        .show()
    }

    private fun openUrl(context: Context, url: String) {
      runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, url.toUri())) }
        .onErr { e -> logcat(ERROR) { e.asLog("Failed to open $url") } }
    }
  }
}
