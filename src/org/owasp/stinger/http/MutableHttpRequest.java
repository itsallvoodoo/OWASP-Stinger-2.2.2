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

package org.owasp.stinger.http;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedList;

import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestWrapper;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class MutableHttpRequest extends HttpServletRequestWrapper {
	
	private HttpServletRequest request = null;
	private ServletRequestWrapper srw = null;
	
	
	private Map headers = new HashMap();
	
	private LinkedList headerNames = new LinkedList();
	
	private Map cookies = new HashMap();
	
	private Map parameters = new HashMap();
	
	public MutableHttpRequest(HttpServletRequest request) {
		super(request);
		this.request = request;
		
		Enumeration e = request.getHeaderNames();
		
		while(e.hasMoreElements()) {
			String name = (String)e.nextElement();
			Enumeration values = request.getHeaders(name);
			headerNames.add(name);
			String lowerName = name.toLowerCase();
			LinkedList list = (LinkedList)headers.get(lowerName);
			
			while (values.hasMoreElements()){
				String value = (String)values.nextElement();
				if(list != null) {
					list.add(value);
				} else {
					list = new LinkedList();
					list.add(value);
					headers.put(lowerName, list);
				}
			}
		}
		
			
		Cookie[] c = request.getCookies();
		
		if(c != null) {
			for(int i=0; i<c.length; i++) {
				cookies.put(c[i].getName(), c[i]);
			}
		}
		
		e = request.getParameterNames();
		
		while(e.hasMoreElements()) {
			String name = (String)e.nextElement();
			String[] values = request.getParameterValues(name);
			
			parameters.put(name, values);
		}
	}
	
	public ServletRequest getRequest() {
		return request;
	}
	
	public String getParameter(String name) {
		String[] values = (String[])parameters.get(name);
		return values!=null? values[0]:null;
	}
	
	public void addParameter(String name, String value) {
		String[] values = (String[])parameters.get(name);
		String[] newValues = new String[values.length+1];
		int i=0;
		for (i=0;i<values.length;i++){
			newValues[i] = values[i];
		}
		newValues[i] = value;
		parameters.put(name, newValues);
	}
	
	public void replaceParameterValue(String name, String oldValue, String newValue) {
		if (name == null || oldValue == null || newValue == null) return;
		String[] values = (String[])parameters.get(name);
		String[] newValues = new String[values.length];
		int i=0;
		for (i=0;i<values.length;i++){
			if (oldValue.equals(values[i])) {
				newValues[i] = newValue;
			}
			else {
				newValues[i] = values[i];
			}
		}
		parameters.put(name, newValues);
	}
	
	public void removeParameter(String name) {
		parameters.remove(name);
	}
	
	public void clearParameters() {
		parameters = new HashMap();
	}
	
	public Map getParameterMap() {
		return new HashMap(parameters);
	}
	
	public Enumeration getParameterNames() {
		return Collections.enumeration(parameters.keySet());
	}
	
	public String[] getParameterValues(String name) {
		
		String[] myVals = (String[])parameters.get(name);
		String[] values = new String[myVals.length];
		
		for(int i=0; i<values.length; i++) {
			values[i] = new String(myVals[i]);
		}
		
		return values;
	}
	
	public Cookie[] getCookies() {
		Collection c = cookies.values();
		Enumeration e = Collections.enumeration(c);
		Cookie[] theCookies = new Cookie[c.size()];
		
		for(int i=0; i<theCookies.length; i++) {
			theCookies[i] = (Cookie)e.nextElement();
		}
		
		return theCookies;
	}
	
	public Cookie getCookie(String name) {
		return (Cookie)cookies.get(name);
	}
	
	public void setCookie(Cookie cookie) {
		cookies.put(cookie.getName(), cookie);
	}
	
	public void addCookie(Cookie cookie) {
		cookies.put(cookie.getName(), cookie);
	}
	
	public long getDateHeader(String name) {
		//FIXME: implement me
		return request.getDateHeader(name);
	}
	
	public String getHeader(String name) {
		String header = null;
		LinkedList values = (LinkedList)headers.get(name.toLowerCase());
		
		if(values != null) {
			header = (String)values.getFirst();
		}
		
		return header;
	}
	
	public void setHeader(String name, String value) {
		LinkedList values = (LinkedList)headers.get(name);
		
		if(values != null) {
			values.add(value);
		} else {
			values = new LinkedList();
			values.add(value);
			headers.put(name, values);
		}
	}
	
	public Enumeration getHeaderNames() {
		return Collections.enumeration(headerNames);
	}
	
	public Enumeration getHeaders(String name) {
		return Collections.enumeration((Collection)headers.get(name.toLowerCase()));
	}
	
	public int getIntHeader(String name) throws NumberFormatException {
		int result = -1;
		LinkedList values = (LinkedList)headers.get(name);
		
		if(values != null) {
			String value = (String)values.getFirst();
			result = Integer.parseInt(value);
		}
		
		return result;
	}
	
}
