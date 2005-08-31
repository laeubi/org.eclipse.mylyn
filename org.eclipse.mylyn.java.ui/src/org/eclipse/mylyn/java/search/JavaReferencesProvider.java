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
/*
 * Created on Feb 18, 2005
  */
package org.eclipse.mylar.java.search;

import org.eclipse.jdt.core.IImportDeclaration;
import org.eclipse.jdt.core.IJavaElement;
import org.eclipse.jdt.core.IMethod;
import org.eclipse.mylar.java.JavaStructureBridge;


/**
 * @author Mik Kersten
 */
public class JavaReferencesProvider extends AbstractJavaRelationshipProvider {

	public static final String ID = ID_GENERIC + ".references";
    public static final String NAME = "Java references";
        
    public JavaReferencesProvider() {
        super(JavaStructureBridge.CONTENT_TYPE, ID);
    }  
    
    @Override
    protected boolean acceptResultElement(IJavaElement element) {
        if (element instanceof IImportDeclaration) return false;
        if (element instanceof IMethod) {
            IMethod method = (IMethod)element;
            if (method.getElementName().startsWith("test")) {
                return false; // HACK
            } else {
                return true;
            }
        }
        return false;
    }
    
    @Override
    protected String getSourceId() {
        return ID;
    }

    @Override
    public String getName() {
        return NAME;
    }
}
