/*
 * Copyright © 2014-2021 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package me.msfjarvis.openpgpktx

import android.os.Parcel
import android.os.Parcelable
import android.os.Parcelable.Creator
import java.time.Instant

public class AutocryptPeerUpdate() : Parcelable {

  private var keyData: ByteArray? = null
  private var effectiveDate: Instant? = null
  private lateinit var preferEncrypt: PreferEncrypt

  internal constructor(
    keyData: ByteArray?,
    effectiveDate: Instant?,
    preferEncrypt: PreferEncrypt,
  ) : this() {
    this.keyData = keyData
    this.effectiveDate = effectiveDate
    this.preferEncrypt = preferEncrypt
  }

  @Suppress("UNUSED_PARAMETER")
  private constructor(source: Parcel, version: Int) : this() {
    keyData = source.createByteArray()
    effectiveDate = if (source.readInt() != 0) Instant.ofEpochMilli(source.readLong()) else null
    preferEncrypt = PreferEncrypt.values()[source.readInt()]
  }

  public fun createAutocryptPeerUpdate(
    keyData: ByteArray?,
    timestamp: Instant?,
  ): AutocryptPeerUpdate {
    return AutocryptPeerUpdate(keyData, timestamp, PreferEncrypt.NOPREFERENCE)
  }

  public fun getKeyData(): ByteArray? {
    return keyData
  }

  public fun hasKeyData(): Boolean {
    return keyData != null
  }

  public fun getEffectiveDate(): Instant? {
    return effectiveDate
  }

  public fun getPreferEncrypt(): PreferEncrypt? {
    return preferEncrypt
  }

  override fun describeContents(): Int {
    return 0
  }

  override fun writeToParcel(dest: Parcel, flags: Int) {
    /**
     * NOTE: When adding fields in the process of updating this API, make sure to bump
     * [.PARCELABLE_VERSION].
     */
    dest.writeInt(PARCELABLE_VERSION)
    // Inject a placeholder that will store the parcel size from this point on
    // (not including the size itself).
    val sizePosition = dest.dataPosition()
    dest.writeInt(0)
    val startPosition = dest.dataPosition()
    // version 1
    dest.writeByteArray(keyData)
    val date = effectiveDate
    if (date != null) {
      dest.writeInt(1)
      dest.writeLong(date.toEpochMilli())
    } else {
      dest.writeInt(0)
    }
    dest.writeInt(preferEncrypt.ordinal)
    // Go back and write the size
    val parcelableSize = dest.dataPosition() - startPosition
    dest.setDataPosition(sizePosition)
    dest.writeInt(parcelableSize)
    dest.setDataPosition(startPosition + parcelableSize)
  }

  public companion object CREATOR : Creator<AutocryptPeerUpdate> {

    private const val PARCELABLE_VERSION = 1

    override fun createFromParcel(source: Parcel): AutocryptPeerUpdate {
      val version = source.readInt() // parcelableVersion
      val parcelableSize = source.readInt()
      val startPosition = source.dataPosition()
      val vr = AutocryptPeerUpdate(source, version)
      // skip over all fields added in future versions of this parcel
      source.setDataPosition(startPosition + parcelableSize)
      return vr
    }

    override fun newArray(size: Int): Array<AutocryptPeerUpdate?> {
      return arrayOfNulls(size)
    }
  }

  public enum class PreferEncrypt {
    NOPREFERENCE,
    MUTUAL,
  }
}
