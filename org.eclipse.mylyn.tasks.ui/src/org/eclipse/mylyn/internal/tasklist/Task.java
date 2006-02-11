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

package org.eclipse.mylar.internal.tasklist;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.eclipse.mylar.core.MylarPlugin;
import org.eclipse.mylar.internal.core.util.MylarStatusHandler;
import org.eclipse.mylar.internal.tasklist.ui.TaskListImages;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.graphics.Image;

/**
 * @author Mik Kersten
 */
public class Task implements ITask {

	private static final String REPOSITORY_KIND_LOCAL = "local";
	
	public enum TaskStatus {
		NOT_STARTED, IN_PROGRESS, COMPLETED;

		@Override
		public String toString() {
			switch (this) {
			case NOT_STARTED:
				return "Not Started";
			case IN_PROGRESS:
				return "In Progress";
			case COMPLETED:
				return "Completed";
			default:
				return "null";
			}
		}
	}

	public enum PriorityLevel {
		P1, P2, P3, P4, P5;
	
		@Override
		public String toString() {
			switch (this) {
			case P1:
				return "P1";
			case P2:
				return "P2";
			case P3:
				return "P3";
			case P4:
				return "P4";
			case P5:
				return "P5";
			default:
				return "P5";
			}
		}
	
		public static PriorityLevel fromString(String string) {
			if (string == null)
				return null;
			if (string.equals("P1"))
				return P1;
			if (string.equals("P2"))
				return P2;
			if (string.equals("P3"))
				return P3;
			if (string.equals("P4"))
				return P4;
			if (string.equals("P5"))
				return P5;
			return null;
		}
	}

	private boolean active = false;

	protected String handle = "-1";

	private boolean category = false;

	private boolean hasReminded = false;

	private String description;

	private String priority = PriorityLevel.P3.toString();

	private String notes = "";

	private int estimatedTimeHours = 0;

	private boolean completed;

	private List<String> links = new ArrayList<String>();

	private List<String> plans = new ArrayList<String>();

	private String url = "";

	private ITaskCategory parentCategory = null;

	private long timeActive = 0;

	private Date completionDate = null;

	private Date creationDate = null;

	private Date reminderDate = null;

	/**
	 * @return null if root
	 */
	private transient ITask parent;

	private List<ITask> children = new ArrayList<ITask>();

	@Override
	public String toString() {
		return description;
	}

	public Task(String handle, String label, boolean newTask) {
		this.handle = handle;
		this.description = label;
		if (newTask) {
			creationDate = new Date();
		}
	}

	public String getHandleIdentifier() {
		return handle;
	}

	public void setHandleIdentifier(String id) {
		this.handle = id;
	}

	public ITask getParent() {
		return parent;
	}

	public void setParent(ITask parent) {
		this.parent = parent;
	}

	/**
	 * Package visible in order to prevent sets that don't update the index.
	 */
	public void setActive(boolean active) {
		this.active = active;
	}

	public boolean isActive() {
		return active;
	}
	
	public String getToolTipText() {
		return getDescription();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Task && obj != null) {
			return this.getHandleIdentifier().compareTo(((Task) obj).getHandleIdentifier()) == 0;
		} else {
			return false;
		}
	}

	@Override
	public int hashCode() {
		return this.getHandleIdentifier().hashCode();
	}

	public boolean isCompleted() {
		return completed;
	}

	public void setCompleted(boolean completed) {
		if (completed) {
			completionDate = new Date();
		}
		this.completed = completed;
	}

	public boolean isCategory() {
		return category;
	}

	public void setIsCategory(boolean category) {
		this.category = category;
	}

	public String getPriority() {
		return priority;
	}

	public void setPriority(String priority) {
		this.priority = priority;
	}

	public List<String> getRelatedLinks() {
		// TODO: removed check for null once xml updated.
		if (links == null) {
			links = new ArrayList<String>();
		}
		return links;
	}

	public void setRelatedLinks(List<String> relatedLinks) {
		this.links = relatedLinks;
	}

	public void addLink(String link) {
		links.add(link);
	}

	public void removeLink(String link) {
		links.remove(link);
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getUrl() {
		return url;
	}

	public String getNotes() {
		// TODO: removed check for null once xml updated.
		if (notes == null) {
			notes = "";
		}
		return notes;
	}

	public void setNotes(String notes) {
		this.notes = notes;
	}

	public long getElapsedTime() {
		return timeActive;
	}

	public void setElapsedTime(long elapsedTime) {
		if (elapsedTime >= 0) {
			this.timeActive = elapsedTime;
		} else {
			MylarStatusHandler.log("Attempt to set negative time on task: " + getDescription(), this);
		}
	}

	public int getEstimateTimeHours() {
		return estimatedTimeHours;
	}

	public void setEstimatedTimeHours(int estimated) {
		this.estimatedTimeHours = estimated;
	}

	public List<ITask> getChildren() {
		return children;
	}

	public void addSubTask(ITask t) {
		children.add(t);
	}

	public void removeSubTask(ITask t) {
		children.remove(t);
	}

	public void setCategory(ITaskCategory cat) {
		this.parentCategory = cat;
	}

	// public void internalSetCategory(TaskCategory cat) {
	// this.parentCategory = cat;
	// }

	public ITaskCategory getCategory() {
		return parentCategory;
	}

	public String getDescription() {
		return description;
	}

	/**
	 * TODO: tasks shouldn't know about images, or the context manager
	 */
	public Image getIcon() {
		if (url != null && !url.trim().equals("") && !url.equals("http://")) {
			return TaskListImages.getImage(TaskListImages.TASK_WEB);
		} else {
			return TaskListImages.getImage(TaskListImages.TASK);
		}
	}

	/**
	 * TODO: tasks shouldn't know about images, or the context manager
	 */
	public Image getStatusIcon() {
		if (isActive()) {
			return TaskListImages.getImage(TaskListImages.TASK_ACTIVE);
		} else {
			if (MylarPlugin.getContextManager().hasContext(handle)) {
				return TaskListImages.getImage(TaskListImages.TASK_INACTIVE_CONTEXT);
			} else {
				return TaskListImages.getImage(TaskListImages.TASK_INACTIVE);
			}
		}
	}

	public boolean isLocal() {
		return true;
	}

	public boolean isActivatable() {
		return true;
	}

	public boolean isDragAndDropEnabled() {
		return true;
	}

	public Font getFont() {
		if (isActive())
			return TaskListImages.BOLD;
		for (ITask child : getChildren()) {
			if (child.isActive())
				return TaskListImages.BOLD;
		}
		return null;
	}

	public Date getCompletionDate() {
		return completionDate;
	}

	public void setReminderDate(Date date) {
		reminderDate = date;
	}

	public Date getReminderDate() {
		return reminderDate;
	}

	public boolean hasBeenReminded() {
		return hasReminded;
	}

	public void setReminded(boolean reminded) {
		this.hasReminded = reminded;
	}

	public Date getCreationDate() {
		if (creationDate == null)
			creationDate = new Date();
		return creationDate;
	}

	public void setCreationDate(Date date) {
		this.creationDate = date;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public void addPlan(String plan) {
		if (plan != null && !plans.contains(plan))
			plans.add(plan);
	}

	public List<String> getPlans() {
		return plans;
	}

	public void setCompletionDate(Date completionDate) {
		this.completionDate = completionDate;
	}

	public boolean isPastReminder() {
		if (reminderDate == null) {
			return false;
		} else {
			Date now = new Date();
			if (reminderDate.compareTo(now) < 0) {
				return true;
			} else {
				return false;
			}
		}
	}

	public boolean hasValidUrl() {
		String taskUrl = getUrl();
		if (taskUrl != null && !taskUrl.equals("") && !taskUrl.equals("http://") && !taskUrl.equals("https://")) {
			try {
				new URL(taskUrl);
				return true;
			} catch (MalformedURLException e) {
				return false;
			}
		}
		return false;
	}

	public TaskStatus getStatus() {
		if (isCompleted()) {
			return TaskStatus.COMPLETED;
		} else {
			return TaskStatus.NOT_STARTED;
		}
	}

	public String getRepositoryKind() {
		return REPOSITORY_KIND_LOCAL;
	}

}
