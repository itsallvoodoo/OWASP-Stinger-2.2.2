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

import java.io.PrintWriter;
import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.violation.Violation;

public class DisplayMessage extends AbstractAction {
	
	public String formatMessage(String message, String bgcolor) {
		StringBuffer buffer = new StringBuffer();
		
		buffer.append("<table width=300 border=1 align=center bgcolor=" + bgcolor + " cellpadding=2\n");
		buffer.append("<tr><td>\n");
		buffer.append("<div align=\"center\" >" + message + "</div>\n");
		buffer.append("</td></tr></table>\n");
		
		return buffer.toString();
	}
	
	public void displayMessage(HttpServletResponse response, String message, String bgcolor) {
		PrintWriter out = null;
		String formatedMessage = formatMessage(message, bgcolor);
		
		try {
			out = response.getWriter();
			out.write(formatedMessage);
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
	
	public void doAction(Violation violation, MutableHttpRequest request, HttpServletResponse response) {
		String message = getParameter("message");
		String bgcolor = getParameter("bgcolor");
		
		displayMessage(response, message, bgcolor);
	}
}
