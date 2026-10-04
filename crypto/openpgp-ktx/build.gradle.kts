/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
@file:Suppress("UnstableApiUsage")

plugins {
  id("com.github.android-password-store.android-library")
  id("com.github.android-password-store.kotlin-android")
}

android {
  defaultConfig { consumerProguardFiles("consumer-proguard-rules.pro") }
  buildFeatures { aidl = true }
  namespace = "me.msfjarvis.openpgpktx"
}

dependencies { implementation(libs.kotlinx.coroutines.core) }
