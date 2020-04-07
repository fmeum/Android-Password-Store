/*
 * Copyright © 2014-2020 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package com.zeapo.pwdstore.ui.adapters

import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.appcompat.view.ActionMode
import androidx.recyclerview.selection.SelectionTracker
import androidx.recyclerview.widget.RecyclerView
import com.zeapo.pwdstore.PasswordFragment
import com.zeapo.pwdstore.PasswordStore
import com.zeapo.pwdstore.R
import com.zeapo.pwdstore.utils.PasswordItem
import java.util.Stack

class PasswordRecyclerAdapter(
    private val activity: PasswordStore,
    private val listener: PasswordFragment.OnFragmentInteractionListener
) : EntryRecyclerAdapter() {

    private val SelectionTracker<Long>.selectedItems: List<PasswordItem>
        get() = selection.map { getItem(it.toInt()) }

    var actionMode: ActionMode? = null
    private val actionModeCallback = object : ActionMode.Callback {

        // Called when the action mode is created; startActionMode() was called
        override fun onCreateActionMode(mode: ActionMode, menu: Menu): Boolean {
            // Inflate a menu resource providing context menu items
            mode.menuInflater.inflate(R.menu.context_pass, menu)
            // hide the fab
            activity.findViewById<View>(R.id.fab).visibility = View.GONE
            return true
        }

        // Called each time the action mode is shown. Always called after onCreateActionMode, but
        // may be called multiple times if the mode is invalidated.
        override fun onPrepareActionMode(mode: ActionMode, menu: Menu): Boolean {
            menu.findItem(R.id.menu_edit_password).isVisible =
                requireSelectionTracker().selectedItems.map { it.type == PasswordItem.TYPE_PASSWORD }
                    .singleOrNull() == true
            return true // Return false if nothing is done
        }

        // Called when the user selects a contextual menu item
        override fun onActionItemClicked(mode: ActionMode, item: MenuItem): Boolean {
            when (item.itemId) {
                R.id.menu_delete_password -> {
                    activity.deletePasswords(
                        this@PasswordRecyclerAdapter,
                        Stack<PasswordItem>().apply {
                            requireSelectionTracker().selectedItems.forEach { push(it) }
                        }
                    )
                    mode.finish() // Action picked, so close the CAB
                    return true
                }
                R.id.menu_edit_password -> {
                    activity.editPassword(requireSelectionTracker().selectedItems.first())
                    mode.finish()
                    return true
                }
                R.id.menu_move_password -> {
                    activity.movePasswords(requireSelectionTracker().selectedItems)
                    return false
                }
                else -> return false
            }
        }

        // Called when the user exits the action mode
        override fun onDestroyActionMode(mode: ActionMode) {
            requireSelectionTracker().selection.forEach { notifyItemChanged(it.toInt()) }
            actionMode = null
            // show the fab
            activity.findViewById<View>(R.id.fab).visibility = View.VISIBLE
        }
    }

    override fun onItemClicked(holder: PasswordItemViewHolder, item: PasswordItem) {
        listener.onFragmentInteraction(item)
    }

    override fun onSelectionChanged() {
        actionMode?.let {
            if (!requireSelectionTracker().hasSelection())
                it.finish()
            else
                it.invalidate()
        } ?: run {
            actionMode = activity.startSupportActionMode(actionModeCallback)
            actionMode?.title = "${requireSelectionTracker().selection.size()}"
            actionMode?.invalidate()
        }
    }
}
