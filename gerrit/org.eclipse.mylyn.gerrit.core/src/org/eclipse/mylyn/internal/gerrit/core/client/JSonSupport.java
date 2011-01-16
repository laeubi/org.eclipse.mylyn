/*********************************************************************
 * Copyright (c) 2010 Sony Ericsson/ST Ericsson and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 *  Contributors:
 *      Sony Ericsson/ST Ericsson - initial API and implementation
 *      Tasktop Technologies - improvements
 *********************************************************************/

package org.eclipse.mylyn.internal.gerrit.core.client;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.eclipse.jgit.diff.Edit;

import com.google.gson.Gson;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gwtjsonrpc.server.JsonServlet;

/**
 * @author Steffen Pingel
 */
public class JSonSupport {

	/**
	 * Parses a Json response.
	 */
	private class JSonResponseDeserializer implements JsonDeserializer<JSonResponse> {
		public JSonResponse deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
				throws JsonParseException {
			JsonObject object = json.getAsJsonObject();
			JSonResponse response = new JSonResponse();
			response.jsonrpc = object.get("jsonrpc").getAsString(); //$NON-NLS-1$
			response.id = object.get("id").getAsInt(); //$NON-NLS-1$
			response.result = object.get("result"); //$NON-NLS-1$
			response.error = object.get("error"); //$NON-NLS-1$			
			return response;
		}
	}

	static class JSonError {

		int code;

		String message;

	}

	static class JsonRequest {

		int id;

		final String jsonrpc = "2.0"; //$NON-NLS-1$

		String method;

		final List<Object> params = new ArrayList<Object>();

		String xsrfKey;
	}

	static class JSonResponse {

		JsonElement error;

		int id;

		String jsonrpc;

		JsonElement result;

	}

	private Gson gson;

	public JSonSupport() {
		gson = JsonServlet.defaultGsonBuilder()
				.registerTypeAdapter(JSonResponse.class, new JSonResponseDeserializer())
				.registerTypeAdapter(Edit.class, new JsonDeserializer<Edit>() {
					public Edit deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
							throws JsonParseException {
						return new Edit(0, 0);
					}
				})
				.create();
	}

	String createRequest(int id, String xsrfKey, String methodName, Collection<Object> args) {
		JsonRequest msg = new JsonRequest();
		msg.method = methodName;
		if (args != null) {
			for (Object arg : args) {
				msg.params.add(arg);
			}
		}
		msg.id = id;
		msg.xsrfKey = xsrfKey;
		return gson.toJson(msg, msg.getClass());
	}

	<T> T parseResponse(String responseMessage, Type resultType) throws GerritException {
		JSonResponse response = gson.fromJson(responseMessage, JSonResponse.class);
		if (response.error != null) {
			JSonError error = gson.fromJson(response.error, JSonError.class);
			throw new GerritException(error.message, error.code);
		} else {
			return gson.fromJson(response.result, resultType);
		}
	}

}
