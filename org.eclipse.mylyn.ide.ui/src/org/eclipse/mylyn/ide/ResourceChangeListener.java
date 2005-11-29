/*******************************************************************************
 * Copyright (c) 2004 - 2005 University Of British Columbia and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     University Of British Columbia - initial API and implementation
 *******************************************************************************/
package org.eclipse.mylar.ide;

import org.eclipse.core.resources.IResourceChangeEvent;
import org.eclipse.core.resources.IResourceChangeListener;
import org.eclipse.core.resources.IResourceDelta;
import org.eclipse.core.resources.IResourceDeltaVisitor;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.mylar.core.MylarPlugin;

/**
 * @author Mik Kersten
 */
public class ResourceChangeListener implements IResourceChangeListener {

	public void resourceChanged(IResourceChangeEvent event) {
		if (event.getType() != IResourceChangeEvent.POST_CHANGE) return;
		IResourceDelta rootDelta = event.getDelta();
		IResourceDeltaVisitor visitor = new IResourceDeltaVisitor() {
			public boolean visit(IResourceDelta delta) {
//				processMarkerDelata(delta.getMarkerDeltas());
				IResourceDelta[] added = delta.getAffectedChildren(IResourceDelta.ADDED);
				for (int i = 0; i < added.length; i++) {
//					IResourceDelta delta2 = added[i];
					
				}
				return true;
			}
		};
		try {
			rootDelta.accept(visitor);
		} catch (CoreException e) {
			MylarPlugin.log(e, "could not accet marker visitor");
		}	
	}
	
//	private void processMarkerDelata(IMarkerDelta[] markers) {
//		for(IMarkerDelta markerDelta: markers){
//			try{
//				final IMarker marker = markerDelta.getMarker();
//				if(marker == null || !marker.exists()){
//					final IMylarStructureBridge bridge = MylarPlugin.getDefault().getStructureBridge(marker.getResource());
//					if(bridge != null){
//						if(!PlatformUI.getWorkbench().getDisplay().isDisposed()) {
//						PlatformUI.getWorkbench().getDisplay().syncExec(new Runnable() {
//				            public void run() {
//				            	MylarPlugin.getContextManager().removeErrorPredictedInterest(bridge.getHandleIdentifier(marker.getResource()), bridge.getContentType(), true);
//				            }});
//						}
//					}
//				}
//					
//				if(markerDelta.getMarker().isSubtypeOf(IMarker.PROBLEM)){
//					final IMylarStructureBridge bridge = MylarPlugin.getDefault().getStructureBridge(marker.getResource());
//					if(bridge != null){
//						if(!PlatformUI.getWorkbench().getDisplay().isDisposed()) {
//							PlatformUI.getWorkbench().getDisplay().syncExec(new Runnable() {
//				            public void run() {
//				            	MylarPlugin.getContextManager().addErrorPredictedInterest(bridge.getHandleIdentifier(marker.getResource()), bridge.getContentType(), true);
//				            }});
//						}
//					}
//				} else {//if(!markerDelta.getMarker().getType().equals("org.eclipse.jdt.core.problem")){
//					final IMylarStructureBridge bridge = MylarPlugin.getDefault().getStructureBridge(marker.getResource());
//					if(bridge != null){
//						if(!PlatformUI.getWorkbench().getDisplay().isDisposed()) {
//							PlatformUI.getWorkbench().getDisplay().syncExec(new Runnable() {
//				            public void run() {
//				            	MylarPlugin.getContextManager().removeErrorPredictedInterest(bridge.getHandleIdentifier(marker.getResource()), bridge.getContentType(), true);
//				            }});
//						}
//					}
//				}
//			}catch (Exception e){
//				MylarPlugin.log(e, " could not update marker");
//			}
//		}
//	}
}