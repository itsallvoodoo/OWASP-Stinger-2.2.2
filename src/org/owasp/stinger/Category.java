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

import java.util.LinkedList;

import org.owasp.stinger.actions.AbstractAction;

public class Category {
	
	public final static String MISSING = "MISSING";
	
	public final static String MALFORMED = "MALFORMED";
	
	private String category = null;
	
	private Severity severity = null;
	
	private LinkedList actions = new LinkedList();
	
	private Category() {
		
	}
	
	public Category(String category, Severity severity) {
		this.category = category;
		this.severity = severity;
	}
	
	public void addAction(AbstractAction action) {
		actions.add(action);
	}
	
	public LinkedList getActions() {
		return actions;
	}
	
	public Severity getSeverity() {
		return severity;
	}
	
	public boolean equals(Object category) {
		boolean result = false;
		
		if(category instanceof String) {
			if(this.category.equalsIgnoreCase((String)category)) {
				result = true;
			}
		} else if(category instanceof Category) {
			if(category.toString().equalsIgnoreCase(this.category)) {
				result = true;
			}
		}
		
		return result;
	}
	
	public int hashCode() {
		return category.hashCode() + severity.toString().hashCode();
	}
	
	public String toString() {
		return category;
	}
}