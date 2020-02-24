package com.zeapo.pwdstore.autofill.oreo

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.util.Log
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import androidx.annotation.RequiresApi
import timber.log.Timber
import java.io.File

private val AUTOFILL_BROWSERS = listOf(
        "org.mozilla.focus",
        "org.mozilla.klar",
        "com.duckduckgo.mobile.android")
private val ACCESSIBILITY_BROWSERS = listOf(
        "org.mozilla.firefox",
        "org.mozilla.firefox_beta",
        "com.microsoft.emmx",
        "com.android.chrome",
        "com.chrome.beta",
        "com.android.browser",
        "com.brave.browser",
        "com.opera.browser",
        "com.opera.browser.beta",
        "com.opera.mini.native",
        "com.chrome.dev",
        "com.chrome.canary",
        "com.google.android.apps.chrome",
        "com.google.android.apps.chrome_dev",
        "com.yandex.browser",
        "com.sec.android.app.sbrowser",
        "com.sec.android.app.sbrowser.beta",
        "org.codeaurora.swe.browser",
        "com.amazon.cloud9",
        "mark.via.gp",
        "org.bromite.bromite",
        "org.chromium.chrome",
        "com.kiwibrowser.browser",
        "com.ecosia.android",
        "com.opera.mini.native.beta",
        "org.mozilla.fennec_aurora",
        "org.mozilla.fennec_fdroid",
        "com.qwant.liberty",
        "com.opera.touch",
        "org.mozilla.fenix",
        "org.mozilla.fenix.nightly",
        "org.mozilla.reference.browser",
        "org.mozilla.rocket",
        "org.torproject.torbrowser",
        "com.vivaldi.browser")
private val ALL_BROWSERS = AUTOFILL_BROWSERS + ACCESSIBILITY_BROWSERS

sealed class FormOrigin(open val identifier: String) {
    data class Web(override val identifier: String) : FormOrigin(identifier)
    data class App(override val identifier: String) : FormOrigin(identifier)
}

@RequiresApi(Build.VERSION_CODES.O)
class Form(structure: AssistStructure, context: Context) {
    private val TAG = "Form"

    private val fillableFields = mutableListOf<FormField>()
    private val ignoredIds = mutableListOf<AutofillId>()
    private val passwordFields by lazy { identifyPasswordFields() }
    private val usernameField by lazy { identifyUsernameField() }

    private var packageName = structure.activityComponent.packageName
    // TODO: Verify signature
    private val isBrowser = packageName in ALL_BROWSERS
    private var originToFill: String? = null

    val canBeFilled by lazy { usernameField != null || passwordFields.isNotEmpty() }
    val canonicalOrigin: FormOrigin?
        get() {
            return if (isBrowser && originToFill != null) {
                val host = Uri.parse(originToFill!!).host ?: return null
                FormOrigin.Web(getCanonicalDomain(host) ?: return null)
            } else {
                FormOrigin.App(packageName)
            }
        }

    init {
        Log.d(TAG, "Request from $packageName (${context.getPackageVerificationId(packageName)})")
        parseStructure(structure)
        Log.d(TAG, "Username field: $usernameField")
        Log.d(TAG, "Password field(s): $passwordFields")
    }

    private fun parseStructure(structure: AssistStructure) {
        for (i in 0 until structure.windowNodeCount) {
            parseViewNode(structure.getWindowNodeAt(i).rootViewNode)
        }
    }

    private fun parseViewNode(node: AssistStructure.ViewNode) {
        val field = FormField(node)
        if (shouldContinueBasedOnOrigin(node) && field.isFillable) {
            Log.d("Form", "$field")
            fillableFields.add(field)
        } else {
            // Log.d("Form", "Found non-fillable field: $field")
            field.autofillId?.let { ignoredIds.add(it) }
        }

        for (i in 0 until node.childCount) {
            parseViewNode(node.getChildAt(i))
        }
    }

    private fun shouldContinueBasedOnOrigin(node: AssistStructure.ViewNode): Boolean {
        if (!isBrowser)
            return true
        val domain = node.webDomain ?: return originToFill == null
        val scheme = (if (Build.VERSION.SDK_INT >= 28) node.webScheme else null) ?: "https"
        if (scheme !in listOf("http", "https"))
            return false
        val origin = "$scheme://$domain"
        if (originToFill == null) {
            Log.d(TAG, "Origin encountered: $origin")
            originToFill = origin
        }
        if (origin != originToFill) {
            Log.d("Form", "Not same-origin field: ${node.className} with origin $origin")
            return false
        }
        return true
    }

    private fun isSingleFieldOrAdjacentPair(fields: List<FormField>): Boolean {
        if (fields.size == 1)
            return true

        if (fields.size != 2)
            return false
        val id0 = fillableFields.indexOf(fields[0])
        val id1 = fillableFields.indexOf(fields[1])
        return Math.abs(id0 - id1) == 1
    }

    private fun isFocusedOrFollowsFocusedUsernameField(field: FormField): Boolean {
        if (field.isFocused)
            return true

        val ownIndex = fillableFields.indexOf(field)
        if (ownIndex == 0)
            return false
        val potentialUsernameField = fillableFields[ownIndex - 1]
        if (!potentialUsernameField.isFocused || !potentialUsernameField.isLikelyUsernameField)
            return false
        return true
    }

    private fun identifyPasswordFields(): List<FormField> {
        val possiblePasswordFields = fillableFields.filter { it.passwordCertainty >= CertaintyLevel.Possible }
        if (possiblePasswordFields.isEmpty())
            return emptyList()
        val certainPasswordFields = fillableFields.filter { it.passwordCertainty >= CertaintyLevel.Certain }
        if (isSingleFieldOrAdjacentPair(certainPasswordFields))
            return certainPasswordFields
        if (certainPasswordFields.count { isFocusedOrFollowsFocusedUsernameField(it) } == 1)
            return certainPasswordFields.filter { isFocusedOrFollowsFocusedUsernameField(it) }
        val likelyPasswordFields = fillableFields.filter { it.passwordCertainty >= CertaintyLevel.Likely }
        if (isSingleFieldOrAdjacentPair(likelyPasswordFields))
            return likelyPasswordFields
        if (likelyPasswordFields.count { isFocusedOrFollowsFocusedUsernameField(it) } == 1)
            return likelyPasswordFields.filter { isFocusedOrFollowsFocusedUsernameField(it) }
        if (isSingleFieldOrAdjacentPair(possiblePasswordFields))
            return possiblePasswordFields
        return emptyList()
    }

    private fun takeFirstBeforePasswordFields(fields: List<FormField>, alwaysTakeSingleField: Boolean = false): FormField? {
        if (fields.isEmpty())
            return null
        if (fields.size == 1 && alwaysTakeSingleField)
            return fields.first()
        if (passwordFields.isEmpty())
            return null
        val firstPasswordIndex = fillableFields.indexOf(passwordFields.first())
        return fields.last { fillableFields.indexOf(it) < firstPasswordIndex }
    }

    private fun identifyUsernameField(): FormField? {
        val possibleUsernameFields = fillableFields.filter { it.usernameCertainty >= CertaintyLevel.Possible }
        if (possibleUsernameFields.isEmpty())
            return null
        val certainUsernameFields = fillableFields.filter { it.usernameCertainty >= CertaintyLevel.Certain }
        var result = takeFirstBeforePasswordFields(certainUsernameFields, alwaysTakeSingleField = true)
        if (result != null)
            return result
        val likelyUsernameFields = fillableFields.filter { it.usernameCertainty >= CertaintyLevel.Likely }
        result = takeFirstBeforePasswordFields(likelyUsernameFields)
        if (result != null)
            return result
        return takeFirstBeforePasswordFields(possibleUsernameFields)
    }

    private fun makeDecryptIntent(file: File, context: Context): Intent {
        return Intent(context, DecryptActivity::class.java).apply {
            putExtra(DecryptActivity.EXTRA_FILE_PATH, file.absolutePath)
        }
    }

    private val clientState by lazy {
        Bundle(2).apply {
            putParcelable(BUNDLE_KEY_USERNAME_ID, usernameField?.autofillId)
            putParcelableArrayList(BUNDLE_KEY_PASSWORD_IDS, passwordFields.map { it.autofillId }.toCollection(ArrayList()))
        }
    }

    private fun makePlaceholderDataset(file: File, context: Context): Dataset {
        val remoteView = makeRemoteView(canonicalOrigin?.identifier ?: "", file.nameWithoutExtension, context)
        return Dataset.Builder(remoteView).run {
            if (usernameField != null)
                usernameField!!.fillWith(this, "PLACEHOLDER")
            for (passwordField in passwordFields) {
                passwordField.fillWith(this, "PLACEHOLDER")
            }
            val decryptIntent = makeDecryptIntent(file, context)
            setAuthentication(PendingIntent.getActivity(context, decryptActivityRequestCode++, decryptIntent, PendingIntent.FLAG_CANCEL_CURRENT).intentSender)
            build()
        }
    }

    fun fillWithAfterDecryption(files: List<File>, context: Context): FillResponse {
        check(canBeFilled)
        return FillResponse.Builder().run {
            for (file in files)
                addDataset(makePlaceholderDataset(file, context))
            setClientState(clientState)
            setIgnoredIds(*ignoredIds.toTypedArray())
            build()
        }
    }

    companion object {

        const val BUNDLE_KEY_USERNAME_ID = "usernameId"
        const val BUNDLE_KEY_PASSWORD_IDS = "passwordIds"

        private var decryptActivityRequestCode = 1

        fun makeFillInDataset(credentials: Credentials, clientState: Bundle, context: Context): Dataset {
            val remoteView = makeRemoteView("PLACEHOLDER", "PLACEHOLDER", context)
            return Dataset.Builder(remoteView).run {
                val usernameId = clientState.getParcelable<AutofillId>(BUNDLE_KEY_USERNAME_ID)
                if (usernameId != null && credentials.username != null)
                    setValue(usernameId, AutofillValue.forText(credentials.username))
                val passwordIds = clientState.getParcelableArrayList<AutofillId>(BUNDLE_KEY_PASSWORD_IDS)
                if (passwordIds != null) {
                    for (passwordId in passwordIds) {
                        setValue(passwordId, AutofillValue.forText(credentials.password))
                    }
                }
                build()
            }
        }
    }
}
