/*******************************************************************************
 * Copyright (c) 2004 - 2006 University Of British Columbia and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     University Of British Columbia - initial API and implementation
 *******************************************************************************/

package org.eclipse.mylar.internal.tasklist.ui.views;

import java.util.Date;

import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.mylar.core.MylarPlugin;
import org.eclipse.mylar.internal.core.util.MylarStatusHandler;
import org.eclipse.mylar.internal.tasklist.TaskListPreferenceConstants;
import org.eclipse.swt.SWT;
import org.eclipse.swt.dnd.Clipboard;
import org.eclipse.swt.dnd.TextTransfer;
import org.eclipse.swt.events.KeyEvent;
import org.eclipse.swt.events.KeyListener;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

/**
 * @author Ken Sueda
 * @author Wesley Coelho (Extended to allow URL input)
 * @author Mik Kersten
 */
public class TaskInputDialog extends Dialog {

	private static final String LABEL_SHELL = "New Personal Task";

	private static final String LABEL_DESCRIPTION = "Description:";

	private String taskName = "";

	private String priority = "P3";

	private String taskURL = "http://";

	private Date reminderDate = null;

	Text taskNameTextWidget = null;

	private Text issueURLTextWidget = null;

	private Button getDescButton = null;

	public TaskInputDialog(Shell parentShell) {
		super(parentShell);
	}

	protected Control createDialogArea(Composite parent) {
		Composite composite = (Composite) super.createDialogArea(parent);
		GridLayout gl = new GridLayout(4, false);
		composite.setLayout(gl);
		GridData data = new GridData(GridData.GRAB_HORIZONTAL | GridData.GRAB_VERTICAL | GridData.HORIZONTAL_ALIGN_FILL
				| GridData.VERTICAL_ALIGN_CENTER);
		data.widthHint = convertHorizontalDLUsToPixels(IDialogConstants.MINIMUM_MESSAGE_AREA_WIDTH + 100);
		composite.setLayoutData(data);

		Label taskNameLabel = new Label(composite, SWT.WRAP);
		taskNameLabel.setText(LABEL_DESCRIPTION);
		taskNameLabel.setFont(parent.getFont());

		taskNameTextWidget = new Text(composite, SWT.SINGLE | SWT.BORDER);
		taskNameTextWidget.setLayoutData(new GridData(GridData.GRAB_HORIZONTAL | GridData.HORIZONTAL_ALIGN_FILL));

		final Combo c = new Combo(composite, SWT.NO_BACKGROUND | SWT.MULTI | SWT.V_SCROLL | SWT.READ_ONLY
				| SWT.DROP_DOWN);
		c.setItems(TaskListView.PRIORITY_LEVELS);
		c.setText(priority);
		c.addSelectionListener(new SelectionListener() {
			public void widgetSelected(SelectionEvent e) {
				priority = c.getText();
			}

			public void widgetDefaultSelected(SelectionEvent e) {
				widgetSelected(e);
			}
		});

		final DatePicker datePicker = new DatePicker(composite, SWT.NULL);
		datePicker.setDateText("<reminder>");
		datePicker.addPickerSelectionListener(new SelectionListener() {
			public void widgetSelected(SelectionEvent arg0) {
				if (datePicker.getDate() != null) {
					reminderDate = datePicker.getDate().getTime();
				}
			}

			public void widgetDefaultSelected(SelectionEvent arg0) {
				// ignore
			}
		});

		Label urlLabel = new Label(composite, SWT.WRAP);
		urlLabel.setText("Web Link:");
		urlLabel.setFont(parent.getFont());

		issueURLTextWidget = new Text(composite, SWT.SINGLE | SWT.BORDER);
		issueURLTextWidget.setText(getDefaultIssueURL());
		GridData urlData = new GridData(GridData.GRAB_HORIZONTAL | GridData.HORIZONTAL_ALIGN_FILL);
		urlData.horizontalSpan = 2;
		issueURLTextWidget.setLayoutData(urlData);

		getDescButton = new Button(composite, SWT.PUSH);
		getDescButton.setText("Get Description");
		getDescButton.setLayoutData(new GridData(GridData.HORIZONTAL_ALIGN_FILL));
		setButtonStatus();

		issueURLTextWidget.addKeyListener(new KeyListener() {
			public void keyPressed(KeyEvent e) {
				setButtonStatus();
			}

			public void keyReleased(KeyEvent e) {
				setButtonStatus();
			}
		});

		getDescButton.addSelectionListener(new SelectionListener() {
			public void widgetSelected(SelectionEvent e) {
				retrieveTaskDescription(issueURLTextWidget.getText());
			}

			public void widgetDefaultSelected(SelectionEvent e) {
			}
		});

		return composite;
	}

	/**
	 * Sets the Get Description button enabled or not depending on whether there
	 * is a URL specified
	 */
	protected void setButtonStatus() {
		String url = issueURLTextWidget.getText();

		if (url.length() > 10 && (url.startsWith("http://") || url.startsWith("https://"))) {
			String defaultPrefix = MylarPlugin.getDefault().getPreferenceStore().getString(
					TaskListPreferenceConstants.DEFAULT_URL_PREFIX);
			if (url.equals(defaultPrefix)) {
				getDescButton.setEnabled(false);
			} else {
				getDescButton.setEnabled(true);
			}
		} else {
			getDescButton.setEnabled(false);
		}
	}

	/**
	 * Returns the default URL text for the task by first checking the contents
	 * of the clipboard and then using the default prefix preference if that
	 * fails
	 */
	protected String getDefaultIssueURL() {

		String clipboardText = getClipboardText();
		if ((clipboardText.startsWith("http://") || clipboardText.startsWith("https://") && clipboardText.length() > 10)) {
			return clipboardText;
		}

		String defaultPrefix = MylarPlugin.getDefault().getPreferenceStore().getString(
				TaskListPreferenceConstants.DEFAULT_URL_PREFIX);
		if (!defaultPrefix.equals("")) {
			return defaultPrefix;
		}

		return taskURL;
	}

	/**
	 * Attempts to set the task pageTitle to the title from the specified url
	 */
	protected void retrieveTaskDescription(final String url) {

		try {
			RetrieveTitleFromUrlJob job = new RetrieveTitleFromUrlJob(issueURLTextWidget.getText()) {

				@Override
				protected void setTitle(final String pageTitle) {
					taskNameTextWidget.setText(pageTitle);
				}

			};
			job.schedule();

		} catch (RuntimeException e) {
			MylarStatusHandler.fail(e, "could not open task web page", false);
		}
	}

	/**
	 * Returns the contents of the clipboard or "" if no text content was
	 * available
	 */
	protected String getClipboardText() {
		Clipboard clipboard = new Clipboard(Display.getDefault());
		TextTransfer transfer = TextTransfer.getInstance();
		String contents = (String) clipboard.getContents(transfer);
		if (contents != null) {
			return contents;
		} else {
			return "";
		}
	}

	public String getSelectedPriority() {
		return priority;
	}

	public String getTaskname() {
		return taskName;
	}

	public Date getReminderDate() {
		return reminderDate;
	}

	public String getIssueURL() {
		return taskURL;
	}

	protected void buttonPressed(int buttonId) {
		if (buttonId == IDialogConstants.OK_ID) {
			taskName = taskNameTextWidget.getText();
			taskURL = issueURLTextWidget.getText();
		} else {
			taskName = null;
		}
		super.buttonPressed(buttonId);
	}

	protected void configureShell(Shell shell) {
		super.configureShell(shell);
		shell.setText(LABEL_SHELL);
	}
}
