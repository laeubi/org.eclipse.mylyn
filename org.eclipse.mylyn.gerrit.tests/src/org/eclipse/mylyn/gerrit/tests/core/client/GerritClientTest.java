/*******************************************************************************
 /*******************************************************************************
 * Copyright (c) 2011, 2013 Tasktop Technologies and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Tasktop Technologies - initial API and implementation
 *     Sascha Scholz (SAP) - improvements
 *     Francois Chouinard (Ericsson)  - Bug 414219 Add new Test
 *     Jacques Bouthillier (Ericsson) - Fix comments for Bug 414219
 *     Jacques Bouthillier (Ericsson) - Bug 414253 Adjust some Test
 *******************************************************************************/

package org.eclipse.mylyn.gerrit.tests.core.client;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.apache.commons.httpclient.Cookie;
import org.eclipse.core.runtime.NullProgressMonitor;
import org.eclipse.mylyn.commons.net.WebLocation;
import org.eclipse.mylyn.commons.net.WebUtil;
import org.eclipse.mylyn.commons.sdk.util.CommonTestUtil;
import org.eclipse.mylyn.gerrit.tests.support.GerritFixture;
import org.eclipse.mylyn.gerrit.tests.support.GerritHarness;
import org.eclipse.mylyn.internal.gerrit.core.GerritUtil;
import org.eclipse.mylyn.internal.gerrit.core.client.GerritAuthenticationState;
import org.eclipse.mylyn.internal.gerrit.core.client.GerritClient;
import org.eclipse.mylyn.internal.gerrit.core.client.GerritConfiguration;
import org.eclipse.mylyn.internal.gerrit.core.client.GerritException;
import org.eclipse.mylyn.internal.gerrit.core.client.GerritSystemInfo;
import org.eclipse.mylyn.internal.gerrit.core.client.compat.CommentLink;
import org.eclipse.mylyn.internal.gerrit.core.client.data.GerritQueryResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.google.gerrit.reviewdb.Account;

/**
 * @author Steffen Pingel
 * @author Sascha Scholz
 * @author Francois Chouinard
 * @author Jacques Bouthillier
 */
public class GerritClientTest extends TestCase {

	private static final String GET_LABELS_OPTION = "LABELS"; //$NON-NLS-1$

	private GerritHarness harness;

	private GerritClient client;

	@Override
	@Before
	public void setUp() throws Exception {
		harness = GerritFixture.current().harness();
		client = harness.client();
	}

	@Override
	@After
	public void tearDown() throws Exception {
		harness.dispose();
	}

	@Test
	public void testRefreshConfig() throws Exception {
		GerritConfiguration config = client.refreshConfig(new NullProgressMonitor());
		assertNotNull(config);
		assertNotNull(config.getGerritConfig());
		assertNotNull(config.getProjects());
	}

	@Test
	public void testGetAccount() throws Exception {
		if (!GerritFixture.current().canAuthenticate()) {
			return; // skip
		}
		Account account = client.getAccount(new NullProgressMonitor());
		assertEquals(CommonTestUtil.getShortUserName(harness.readCredentials()), account.getUserName());
	}

	@Test
	public void testGetAccountAnonymous() throws Exception {
		client = harness.clientAnonymous();
		try {
			client.getAccount(new NullProgressMonitor());
			fail("Expected GerritException");
		} catch (GerritException e) {
			assertEquals("Not Signed In", e.getMessage());
		}
	}

	@Test
	public void testGetInfo() throws Exception {
		GerritSystemInfo info = client.getInfo(new NullProgressMonitor());
		if (GerritFixture.current().canAuthenticate()) {
			assertEquals(CommonTestUtil.getShortUserName(harness.readCredentials()), info.getFullName());
		} else {
			assertEquals("Anonymous", info.getFullName());
		}
	}

	@Test
	public void testRefreshConfigCommentLinks() throws Exception {
		if (!GerritFixture.current().canAuthenticate()
				|| !GerritFixture.current().getCapabilities().supportsCommentLinks()) {
			return; // skip
		}

		List<CommentLink> expected = new ArrayList<CommentLink>();
		expected.add(new CommentLink("(I[0-9a-f]{8,40})", "<a href=\"#q,$1,n,z\">$&</a>"));
		expected.add(new CommentLink("(bug\\s+)(\\d+)", "<a href=\"http://bugs.mylyn.org/show_bug.cgi?id=$2\">$&</a>"));
		expected.add(new CommentLink("([Tt]ask:\\s+)(\\d+)", "$1<a href=\"http://tracker.mylyn.org/$2\">$2</a>"));

		client = harness.client();
		GerritConfiguration config = client.refreshConfig(new NullProgressMonitor());
		List<CommentLink> links = config.getGerritConfig().getCommentLinks2();
		assertEquals(expected, links);
	}

	@Test
	public void testInvalidXrsfKey() throws Exception {
		if (!GerritFixture.current().canAuthenticate()) {
			return;
		}

		WebLocation location = harness.location();
		GerritAuthenticationState authState = new GerritAuthenticationState();
		authState.setCookie(new Cookie(WebUtil.getHost(location.getUrl()), "xrsfKey", "invalid"));
		client = new GerritClient(null, location, null, authState, "invalid");
		client.getAccount(null);
	}

	@Test
	public void testGetVersion() throws Exception {
		assertEquals(GerritFixture.current().getGerritVersion(), client.getVersion(new NullProgressMonitor()));
	}

	private List<GerritQueryResult> executeQuery(String query) throws GerritException {
		List<GerritQueryResult> results = null;
		results = client.executeQuery(new NullProgressMonitor(), query);
		return results;
	}

	private List<GerritQueryResult> executeQuery(String query, String option) throws GerritException {
		List<GerritQueryResult> results = null;
		results = client.executeQuery(new NullProgressMonitor(), query, option);
		return results;
	}

	@Test
	public void testExecuteQueryWithoutOption() throws Exception {
		String query = "status:open";
		List<GerritQueryResult> results = executeQuery(query);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryWithNullOption() throws Exception {
		String query = "status:open";
		String option = null;
		List<GerritQueryResult> results = executeQuery(query, option);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryWithEmptyOption() throws Exception {
		String query = "status:open";
		String option = "";
		List<GerritQueryResult> results = executeQuery(query, option);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryWithOption() throws Exception {
		String query = "status:open";
		String option = GET_LABELS_OPTION;
		List<GerritQueryResult> results = executeQuery(query, option);
		assertNotNull(results);
		for (int index = 0; index < results.size(); index++) {
			assertNotNull(results.get(index));
			assertNotNull(results.get(index).getReviewLabel());
		}
	}

	private List<GerritQueryResult> executeQueryRest(String query) throws GerritException {
		return client.executeQueryRest(new NullProgressMonitor(), query);
	}

	private List<GerritQueryResult> executeQueryRest(String query, String option) throws GerritException {
		return client.executeQueryRest(new NullProgressMonitor(), query, option);
	}

	@Test
	public void testExecuteQueryRestWithoutOption() throws Exception {
		String query = "status:open";
		List<GerritQueryResult> results = executeQueryRest(query);

		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryRestWithNullOption() throws Exception {
		String query = "status:open";
		String option = null;
		List<GerritQueryResult> results = executeQueryRest(query, option);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryRestWithEmptyOption() throws Exception {
		String query = "status:open";
		String option = "";
		List<GerritQueryResult> results = null;
		results = executeQueryRest(query, option);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryvWithOption() throws Exception {
		String query = "status:open";
		String option = GET_LABELS_OPTION;
		List<GerritQueryResult> results = executeQuery(query, option);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryAllMerged() throws GerritException {
		String query = "status:merged";
		String option = GET_LABELS_OPTION;
		List<GerritQueryResult> results = executeQuery(query, option);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryAllAbandoned() throws GerritException {
		String query = "status:abandoned";
		String option = GET_LABELS_OPTION;
		List<GerritQueryResult> results = executeQuery(query, option);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryisStarred() throws GerritException {
		String query = "is:starred status:open";
		String option = GET_LABELS_OPTION;
		List<GerritQueryResult> results = executeQuery(query, option);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryHasComments() throws GerritException {
		String query = "has:draft";
		List<GerritQueryResult> results = executeQuery(query);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryDraftsCommentsReviews() throws GerritException {
		String query = "has:draft";
		List<GerritQueryResult> results = executeQuery(query);
		assertNotNull(results);
	}

	@Test
	public void testExecuteQueryDraftsReviews() throws GerritException {
		String query = "is:draft";
		List<GerritQueryResult> results = executeQuery(query);
		assertNotNull(results);
	}

	@Test
	public void testToReviewId() throws GerritException {
		assertEquals("123", client.toReviewId("123", null));
		assertEquals("1", client.toReviewId("1", null));
	}

	@Test
	public void testToReviewIdWithInvalidId() {
		try {
			client.toReviewId("invalidid", null);
			fail("Expected GerritException");
		} catch (GerritException e) {
			assertEquals("invalidid is not a valid review ID", e.getMessage());

		}
	}

	@Test
	public void testToReviewIdWithChangeId() throws Exception {
		harness.ensureOneReviewExists();
		List<GerritQueryResult> results = executeQuery("status:open");
		GerritQueryResult result = results.get(0);
		String reviewId = Integer.toString(result.getNumber());
		String changeId = GerritUtil.toChangeId(result.getId());
		assertEquals(reviewId, client.toReviewId(changeId, null));
	}

	@Test
	public void testIsZippedContent() throws Exception {
		assertTrue(GerritClient.isZippedContent("PK\u0003\u0004somezippedcontent".getBytes()));
		assertFalse(GerritClient.isZippedContent("PK\u0003notzippedcontent".getBytes()));
		assertFalse(GerritClient.isZippedContent("PKnotzippedcontent".getBytes()));
		assertFalse(GerritClient.isZippedContent("notzippedcontent".getBytes()));
		assertFalse(GerritClient.isZippedContent("PK".getBytes()));
		assertFalse(GerritClient.isZippedContent("".getBytes()));
		assertFalse(GerritClient.isZippedContent(null));
	}

}
