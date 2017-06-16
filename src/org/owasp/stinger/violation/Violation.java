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

package org.owasp.stinger.violation;

import java.util.LinkedList;

import org.owasp.stinger.Category;
import org.owasp.stinger.Severity;

public class Violation {
	
	private Category category = null;
	
	private String uri = null;
	
	private String regex = null;
	
	private String name = null;
	
	private String value = null;
	
	public Violation() {
		
	}
	
	public Violation(Category category, String name, String value, String regex, String uri) {
		this.category = category;
		this.name = name;
		this.value = value;
		this.regex = regex;
		this.uri = uri;
	}
	
	public Category getCategory() {
		return category;
	}
	
	public void setCategory(Category category) {
		this.category = category;
	}
	
	public Severity getSeverity() {
		return category.getSeverity();
	}
	
	public String getUri() {
		return uri;
	}
	
	public void setUri(String uri) {
		this.uri = uri;
	}
	
	public String getRegEx() {
		return regex;
	}
	
	public void setRegEx(String regex) {
		this.regex = regex;
	}
	
	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public String getValue() {
		return value;
	}
	
	public void setValue(String value) {
		this.value = value;
	}
	
	public LinkedList getActions() {
		return category.getActions();
	}
}
