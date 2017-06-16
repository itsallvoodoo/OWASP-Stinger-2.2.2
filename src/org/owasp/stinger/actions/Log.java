/**
 * Stinger is an HTTP Request Validation Engine
 * Copyright (C) 2006  Aspect Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Contact us at info@aspectsecurity.com or www.aspectsecurity.com
 *
 */

package org.owasp.stinger.actions;

import java.io.IOException;

import java.util.logging.Logger;
import java.util.logging.LogRecord;
import java.util.logging.Level;
import java.util.logging.FileHandler;

import javax.servlet.http.HttpServletResponse;

import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.violation.Violation;

public class Log extends AbstractAction {
	
	private static Logger logger = Logger.getLogger("org.owasp.stinger.actions.Log");
	
	private static FileHandler handler = null;
	
	public Log() {
		
	}
	
	public void doAction(Violation violation, MutableHttpRequest request, HttpServletResponse response) {
		FileHandler handler = null;
		String log = getParameter("log");
		String level = getParameter("level");
		String message = getParameter("message");
		String limit = getParameter("limit");
		String count = getParameter("count");
		String append = getParameter("append");
		
		/** Offender's IP **/
		message = message.replaceAll("%ip", request.getRemoteAddr());
		
		/** Offender's Port **/
//		message = message.replaceAll("%port", String.valueOf(request.getRemotePort()));
		
		/** Offending parameter name **/
		if(violation.getName() != null) {
			message = message.replaceAll("%name", violation.getName());
		} else {
			message = message.replaceAll("%name", "NULL");
		}
		
		/** Offending parameter value **/
		if(violation.getValue() != null) {
			message = message.replaceAll("%value", violation.getValue());
		} else {
			message = message.replaceAll("%value", "NULL");
		}
		
		/** Offending parameter value HTML Encoded **/
		if(violation.getValue() != null) {
			message = message.replaceAll("%encoded_value", violation.getValue());
		} else {
			message = message.replaceAll("%encoded_value", "NULL");
		}
		
		/** Offender's JSESSIONID **/
		if(request.getCookie("JSESSIONID") != null) {
			message = message.replaceAll("%js", request.getCookie("JSESSIONID").getValue());
		} else {
			message = message.replaceAll("%js", "NULL");
		}
		
		if(handler == null) {
			handler = getHandler(log, limit, count, append);
			logger.addHandler(handler);
		}
		
		logger.log(new LogRecord(Level.parse(level.toUpperCase()), message));
		handler.flush();
		//handler.close();
	}
	
	private synchronized FileHandler getHandler(String log, String limit, String count, String append) {
		int l = -1;
		int c = -1;
		boolean a = false;
		
		try {
			l = Integer.parseInt(limit);
			c = Integer.parseInt(count);
			a = Boolean.getBoolean(append);
		} catch (NumberFormatException nfe) {
			nfe.printStackTrace();
			l = 1024 * 1024;
			c = 1;
			return getHandler(log, l, c, a);
		}
		
		return getHandler(log, l, c, a);
	}
	
	private synchronized FileHandler getHandler(String log, int limit, int count, boolean append) {
		
		try {
			handler = new FileHandler(log, limit, count, append);
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
		return handler;
	}
}
