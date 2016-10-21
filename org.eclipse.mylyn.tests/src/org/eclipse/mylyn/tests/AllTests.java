/*******************************************************************************
 * Copyright (c) 2004, 2010 Tasktop Technologies and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Tasktop Technologies - initial API and implementation
 *******************************************************************************/

package org.eclipse.mylyn.tests;

import org.eclipse.mylyn.commons.sdk.util.ManagedSuite;
import org.eclipse.mylyn.commons.sdk.util.ManagedTestSuite;
import org.eclipse.mylyn.commons.sdk.util.TestConfiguration;

import junit.framework.JUnit4TestAdapter;
import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * @author Mik Kersten
 */
public class AllTests {

	public static Test suite() {
		TestConfiguration configuration = ManagedSuite.getTestConfiguration();
		if (configuration == null) {
			configuration = new TestConfiguration();
			ManagedSuite.setTestConfiguration(configuration);
		}

		TestSuite suite = new ManagedTestSuite(AllTests.class.getName());
		AllNonConnectorTests.addTests(suite, configuration);
		suite.addTest(new JUnit4TestAdapter(AllConnectorTests.class));
		return suite;
	}

}
