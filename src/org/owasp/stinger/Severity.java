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

package org.owasp.stinger;

public class Severity  {
	
	public final static Severity IGNORE = new Severity("IGNORE");
	
	public final static Severity CONTINUE = new Severity("CONTINUE");
	
	public final static Severity FATAL = new Severity("FATAL");
	
	private String type = null;
	
	private Severity() {
		
	}
	
	private Severity(String type) {
		this.type = type;
	}
	
	public static Severity valueOf(String severity) {
		if(severity == null) {
			return null;
		} else if(IGNORE.equals(severity)) {
			return IGNORE;
		} else if(CONTINUE.equals(severity)) {
			return CONTINUE;
		} else if(FATAL.equals(severity)) {
			return FATAL;
		} else {
			return null;
		}
	}
	
	public boolean equals(Object type) {
		boolean result = false;
		
		if(type instanceof String) {
			if(this.type.equalsIgnoreCase((String)type)) {
				result = true;
			}
		} else if(type instanceof Severity) {
			if(type.toString().equalsIgnoreCase(this.type)) {
				result = true;
			}
		}
		
		return result;
	}
	
	public int hashCode() {
		return type.hashCode();
	}
	
	public String toString() {
		return type;
	}
}
