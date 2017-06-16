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

package org.owasp.stinger.rules;

import java.util.LinkedList;
import java.util.regex.Pattern;

import org.owasp.stinger.Category;

public class Rule {
	
	private String name = null;
	
	private Pattern pattern = null;
	
	private Category missing = null;
	
	private Category malformed = null;
	
	public Rule() {
		
	}
	
	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public String getPattern() {
		return pattern.pattern();
	}
	
	public void setPattern(String regex) {
		this.pattern = Pattern.compile(regex);
	}
	
	public Category getMissing() {
		return missing;
	}
	
	public void setMissing(Category missing) {
		this.missing = missing;
	}
	
	public LinkedList getMissingActions() {
		return missing.getActions();
	}
	
	public Category getMalformed() {
		return malformed;
	}
	
	public void setMalformed(Category malformed) {
		this.malformed = malformed;
	}
	
	public LinkedList getMalformedActions() {
		return malformed.getActions();
	}
	
	public boolean isValid(String value) {
		return pattern.matcher(value).matches();
	}
}
