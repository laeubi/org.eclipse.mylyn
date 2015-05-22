/*******************************************************************************
 * Copyright (c) 2010, 2011 Tasktop Technologies and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Tasktop Technologies - initial API and implementation
 *******************************************************************************/

package org.eclipse.mylyn.internal.team.ui.history;

import org.eclipse.jface.viewers.ITreeContentProvider;
import org.eclipse.jface.viewers.Viewer;
import org.eclipse.mylyn.tasks.core.data.TaskHistory;
import org.eclipse.mylyn.tasks.core.data.TaskRevision;

/**
 * @author Steffen Pingel
 */
public class TaskHistoryContentProvider implements ITreeContentProvider {

	private static final Object[] EMPTY_ARRAY = new Object[0];

	public TaskHistoryContentProvider() {
	}

	public void dispose() {
		// ignore
	}

	public Object[] getChildren(Object parentElement) {
		if (parentElement instanceof TaskRevision) {
			return ((TaskRevision) parentElement).getChanges().toArray();
		}
		return EMPTY_ARRAY;
	}

	public Object[] getElements(Object inputElement) {
		if (inputElement instanceof TaskHistory) {
			return ((TaskHistory) inputElement).getRevisions().toArray();
		}
		return EMPTY_ARRAY;
	}

	public Object getParent(Object element) {
		return null;
	}

	public boolean hasChildren(Object element) {
		if (element instanceof TaskRevision) {
			return getChildren(element).length > 1;
		}
		return getChildren(element).length > 0;
	}

	public void inputChanged(Viewer viewer, Object oldInput, Object newInput) {
	}

}
